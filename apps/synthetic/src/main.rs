#![feature(duration_extras)]
#![feature(duration_from_micros)]
#![feature(nll)]
#![feature(test)]
#![feature(if_while_or_patterns)]

#[macro_use]
extern crate clap;

extern crate bincode;
extern crate byteorder;
extern crate dns_parser;
extern crate libc;
extern crate lockstep;
extern crate rand;
extern crate shenango;
extern crate test;

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::slice;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{App, Arg};
use rand::distributions::{Exp, IndependentSample};
use rand::Rng;
use shenango::udp::UdpSpawner;

mod backend;
use backend::*;

mod payload;
use payload::Payload;

#[derive(Default)]
pub struct Packet {
    work_iterations: u64,
    randomness: u64,
    target_start: Duration,
    actual_start: Option<Duration>,
    completion_time: Option<Duration>,
}

mod memcache_error;
mod memcache_packet;
mod memcached;

mod dns;

#[derive(Copy, Clone, Debug)]
enum Distribution {
    Zero,
    Constant(u64),
    Exponential(f64),
    Bimodal1(f64),
    Bimodal2(f64),
}
impl Distribution {
    fn name(&self) -> &'static str {
        match *self {
            Distribution::Zero => "zero",
            Distribution::Constant(_) => "constant",
            Distribution::Exponential(_) => "exponential",
            Distribution::Bimodal1(_) => "bimodal1",
            Distribution::Bimodal2(_) => "bimodal2",
        }
    }
    fn sample<R: Rng>(&self, rng: &mut R) -> u64 {
        match *self {
            Distribution::Zero => 0,
            Distribution::Constant(m) => m,
            Distribution::Exponential(m) => Exp::new(1.0 / m).ind_sample(rng) as u64,
            Distribution::Bimodal1(m) => {
                if rng.gen_weighted_bool(10) {
                    (m * 5.5) as u64
                } else {
                    (m * 0.5) as u64
                }
            }
            Distribution::Bimodal2(m) => {
                if rng.gen_weighted_bool(1000) {
                    (m * 500.5) as u64
                } else {
                    (m * 0.5) as u64
                }
            }
        }
    }
}

#[derive(Copy, Clone)]
enum Protocol {
    Synthetic,
    Memcached,
    Dns,
}

#[derive(Copy, Clone)]
enum OutputMode {
    Silent,
    Normal,
    WithHeader,
    Trace,
    IncludeRaw,
    IncludeRawWithHeader,
}

#[allow(unused)]
#[inline(always)]
fn sqrt_work(iterations: u64) {
    let k = 2350845.545;
    for i in 0..iterations {
        test::black_box(f64::sqrt(k * i as f64));
    }
}

static mut STRIDED_MEMTOUCH_STRIDE: usize = 1;
static mut STRIDED_MEMTOUCH_BUFFER: Option<Vec<u8>> = None;

#[inline(always)]
fn work(iterations: u64) {
    let buffer = unsafe { STRIDED_MEMTOUCH_BUFFER.as_ref().unwrap() };
    for i in 0..(iterations as usize) {
        test::black_box::<u8>(unsafe { buffer[(i * STRIDED_MEMTOUCH_STRIDE) % buffer.len()] });
    }
}

fn duration_to_ns(duration: Duration) -> u64 {
    (duration.as_secs() * 1000_000_000 + duration.subsec_nanos() as u64)
}

fn run_server(backend: Backend, socket: UdpConnection, nthreads: u32) {
    let socket = Arc::new(socket);
    let join_handles: Vec<_> = (0..nthreads)
        .map(|_| {
            let socket2 = socket.clone();
            backend.spawn_thread(move || {
                let mut buf = vec![0; 4096];
                loop {
                    let (len, remote_addr) = socket2.recv_from(&mut buf[..]).unwrap();

                    let payload: Payload = bincode::deserialize(&buf[..len]).unwrap();
                    work(payload.work_iterations);
                    socket2.send_to(&buf[..len], remote_addr).unwrap();
                }
            })
        })
        .collect();

    for j in join_handles {
        j.join().unwrap();
    }
}

fn run_spawner_server(addr: SocketAddrV4) {
    extern "C" fn echo(d: *mut shenango::ffi::udp_spawn_data) {
        unsafe {
            let buf = slice::from_raw_parts((*d).buf as *mut u8, (*d).len);
            let payload: Payload = bincode::deserialize(buf).unwrap();
            work(payload.work_iterations);
            let _ = UdpSpawner::reply(d, buf);
            UdpSpawner::release_data(d);
        }
    }

    let _s = unsafe { UdpSpawner::new(addr, echo).unwrap() };

    loop {
        shenango::sleep(Duration::from_secs(10));
    }
}

fn run_client(
    backend: Backend,
    addr: SocketAddrV4,
    runtime: Duration,
    packets_per_second: usize,
    nthreads: u32,
    output: OutputMode,
    protocol: Protocol,
    distribution: Distribution,
    barrier_group: &mut Option<lockstep::Group>,
) -> bool {
    let packets_per_thread =
        duration_to_ns(runtime) as usize * packets_per_second / (1000_000_000 * nthreads as usize);
    let ns_per_packet = nthreads as usize * 1000_000_000 / packets_per_second;

    let exp = Exp::new(1.0 / ns_per_packet as f64);
    let mut rng = rand::thread_rng();
    let packet_schedules: Vec<(Vec<Packet>, Vec<Option<Duration>>)> = (0..nthreads)
        .map(|_| {
            let mut last = 100_000_000;
            let mut packets = Vec::with_capacity(packets_per_thread);
            for _ in 0..packets_per_thread {
                last += exp.ind_sample(&mut rng) as u64;
                packets.push(Packet {
                    randomness: rng.gen::<u64>(),
                    target_start: Duration::from_nanos(last),
                    work_iterations: distribution.sample(&mut rng),
                    ..Default::default()
                });
            }
            (packets, vec![None; packets_per_thread])
        })
        .collect();

    if let Some(ref mut g) = *barrier_group {
        g.barrier();
    }
    let start = Instant::now();

    let mut send_threads = Vec::new();
    let mut receive_threads = Vec::new();
    for (mut packets, mut receive_times) in packet_schedules {
        let socket =
            Arc::new(backend.create_udp_connection("0.0.0.0:0".parse().unwrap(), Some(addr)));
        let socket2 = socket.clone();

        receive_threads.push(backend.spawn_thread(move || {
            let mut recv_buf = vec![0; 4096];
            for _ in 0..receive_times.len() {
                match socket.recv(&mut recv_buf[..]) {
                    Ok(len) => {
                        if len == 0 {
                            continue;
                        }
                        let idx = match protocol {
                            Protocol::Memcached => memcached::parse_response(&recv_buf[..len]),
                            Protocol::Synthetic => payload::parse_response(&recv_buf[..len]),
                            Protocol::Dns => dns::parse_response(&recv_buf[..len]),
                        };
                        if idx.is_err() {
                            println!("Error parsing response");
                            continue;
                        }
                        receive_times[idx.unwrap() as usize] = Some(start.elapsed());
                    }
                    Err(e) => {
                        match e.raw_os_error() {
                            Some(-108) => {} // -ESHUTDOWN
                            _ => println!("Receive thread: {}", e),
                        }
                        break;
                    }
                }
            }
            receive_times
        }));
        send_threads.push(backend.spawn_thread(move || {
            // If the send or receive thread is still running 500 ms after it should have finished,
            // then stop it by triggering a shutdown on the socket.
            let socket = socket2.clone();
            backend.spawn_thread(move || {
                backend.sleep(runtime + Duration::from_millis(500));
                if Arc::strong_count(&socket) > 1 {
                    socket.shutdown();
                }
            });

            let mut payload = Vec::with_capacity(4096);
            for (i, packet) in packets.iter_mut().enumerate() {
                payload.clear();
                match protocol {
                    Protocol::Memcached => memcached::create_request(i, packet, &mut payload),
                    Protocol::Synthetic => payload::create_request(i, packet, &mut payload),
                    Protocol::Dns => dns::create_request(i, packet, &mut payload),
                };

                let t = start.elapsed();
                if t < packet.target_start {
                    backend.sleep(packet.target_start - t);
                }
                if start.elapsed() > packet.target_start + Duration::from_micros(5) {
                    continue;
                }

                packet.actual_start = Some(start.elapsed());
                if let Err(e) = socket2.send(&payload[..]) {
                    println!("Send thread: {}", e);
                    break;
                }
            }

            packets
        }))
    }

    let mut packets: Vec<_> = send_threads
        .into_iter()
        .zip(receive_threads.into_iter())
        .flat_map(|(s, r)| {
            s.join()
                .unwrap()
                .into_iter()
                .zip(r.join().unwrap().into_iter())
        })
        .map(|(p, r)| Packet {
            completion_time: r,
            ..p
        })
        .collect();
    packets.sort_by_key(|p| p.target_start);

    // Discard the first 10% of the packets.
    let mut packets = packets.split_off(packets.len() / 10);

    let never_sent = packets.iter().filter(|p| p.actual_start.is_none()).count();
    let dropped = packets
        .iter()
        .filter(|p| p.completion_time.is_none())
        .count() - never_sent;
    if packets.len() - dropped - never_sent <= 1 {
        match output {
            OutputMode::Silent => {}
            OutputMode::WithHeader
            | OutputMode::IncludeRawWithHeader
            | OutputMode::Normal
            | OutputMode::IncludeRaw => {
                println!(
                    "{}, {}, 0, {}, {}",
                    distribution.name(),
                    packets_per_second,
                    dropped,
                    never_sent,
                );
            }
            OutputMode::Trace => {
                println!("Warning: missing *all* of the packets");
                println!(
                    "Dropped: {}, Never sent: {}, Total packets: {}",
                    dropped,
                    never_sent,
                    packets.len()
                );
            }
        }
        return false;
    }

    let first_send = packets.iter().filter_map(|p| p.actual_start).min().unwrap();
    let last_send = packets.iter().filter_map(|p| p.actual_start).max().unwrap();
    let mut latencies: Vec<_> = packets
        .iter()
        .filter_map(|p| match (p.actual_start, p.completion_time) {
            (Some(ref start), Some(ref end)) => Some(*end - *start),
            (Some(_), None) => Some(Duration::from_secs(9999)),
            (None, None) => None,
            (None, Some(_)) => unreachable!(),
        })
        .collect();
    latencies.sort();

    if let OutputMode::WithHeader | OutputMode::IncludeRawWithHeader = output {
        println!("Distribution, Target, Actual, Dropped, Never Sent, Median, 90th, 99th, 99.9th, 99.99th");
    }
    match output {
        OutputMode::Silent => {}
        OutputMode::WithHeader
        | OutputMode::IncludeRawWithHeader
        | OutputMode::Normal
        | OutputMode::IncludeRaw => {
            let percentile = |p| {
                duration_to_ns(latencies[(latencies.len() as f32 * p / 100.0) as usize]) as f32
                    / 1000.0
            };

            println!(
                "{}, {}, {}, {}, {}, {:.1}, {:.1}, {:.1}, {:.1}, {:.1}",
                distribution.name(),
                packets_per_second,
                latencies.len() as u64 * 1000_000_000 / duration_to_ns(last_send - first_send),
                dropped,
                never_sent,
                percentile(50.0),
                percentile(90.0),
                percentile(99.0),
                percentile(99.9),
                percentile(99.99)
            );
        }
        OutputMode::Trace => {
            packets.sort_by_key(|p| p.actual_start.unwrap_or(p.target_start));
            for p in packets {
                if let Some(completion_time) = p.completion_time {
                    let actual_start = p.actual_start.unwrap();
                    println!(
                        "{} {} {}",
                        duration_to_ns(actual_start),
                        duration_to_ns(actual_start - p.target_start),
                        duration_to_ns(completion_time - actual_start)
                    )
                } else if p.actual_start.is_some() {
                    let actual_start = p.actual_start.unwrap();
                    println!(
                        "{} {} -1",
                        duration_to_ns(actual_start),
                        duration_to_ns(actual_start - p.target_start),
                    )
                } else {
                    println!("{} -1 -1", duration_to_ns(p.target_start))
                }
            }
        }
    }
    if let OutputMode::IncludeRaw | OutputMode::IncludeRawWithHeader = output {
        let mut buckets = BTreeMap::new();

        for l in latencies {
            *buckets.entry(duration_to_ns(l) / 1000).or_insert(0) += 1;
        }
        print!("Latencies: ");
        for k in buckets.keys() {
            print!("{}:{} ", k, buckets[k]);
        }
        println!("");
    }
    true
}
fn main() {
    let matches = App::new("Synthetic Workload Application")
        .version("0.1")
        .arg(
            Arg::with_name("ADDR")
                .index(1)
                .help("Address and port to listen on")
                .required(true),
        )
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("T")
                .default_value("1")
                .help("Number of client threads"),
        )
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .value_name("MODE")
                .possible_values(&[
                    "linux-server",
                    "linux-client",
                    "runtime-server",
                    "runtime-client",
                    "spawner-server",
                    "work-bench",
                ])
                .required(true)
                .requires_ifs(&[
                    ("runtime-server", "config"),
                    ("runtime-client", "config"),
                    ("spawner-server", "config"),
                ])
                .help("Which mode to run in"),
        )
        .arg(
            Arg::with_name("runtime")
                .short("r")
                .long("runtime")
                .takes_value(true)
                .default_value("10")
                .help("How long the application should run for"),
        )
        .arg(
            Arg::with_name("mpps")
                .long("mpps")
                .takes_value(true)
                .default_value("0.02")
                .help("How many *million* packets should be sent per second"),
        )
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("trace")
                .long("trace")
                .takes_value(false)
                .help("Whether to output trace of all packet latencies."),
        )
        .arg(
            Arg::with_name("protocol")
                .short("p")
                .long("protocol")
                .value_name("PROTOCOL")
                .possible_values(&["synthetic", "memcached", "dns"])
                .default_value("synthetic")
                .help("Which client protocol to speak"),
        )
        .arg(
            Arg::with_name("warmup")
                .long("warmup")
                .takes_value(false)
                .help("Run the warmup routine"),
        )
        .arg(
            Arg::with_name("distribution")
                .long("distribution")
                .short("d")
                .takes_value(true)
                .possible_values(&["zero", "constant", "exponential", "bimodal1", "bimodal2"])
                .default_value("zero")
                .help("Distribution of request lengths to use"),
        )
        .arg(
            Arg::with_name("mean")
                .long("mean")
                .takes_value(true)
                .default_value("167")
                .help("Mean number of work iterations per request"),
        )
        .arg(
            Arg::with_name("barrier-peers")
                .long("barrier-peers")
                .requires("barrier-leader")
                .takes_value(true)
                .help("Number of peers in barrier group"),
        )
        .arg(
            Arg::with_name("barrier-leader")
                .long("barrier-leader")
                .requires("barrier-peers")
                .takes_value(true)
                .help("Leader of barrier group"),
        )
        .arg(
            Arg::with_name("samples")
                .long("samples")
                .takes_value(true)
                .default_value("20")
                .help("Number of samples to collect"),
        )
        .arg(
            Arg::with_name("strided-size")
                .long("strided-size")
                .takes_value(true)
                .default_value("1024")
                .help("Amount of memory to use for strided-memtouch fake work"),
        )
        .arg(
            Arg::with_name("strided-stride")
                .long("strided-stride")
                .takes_value(true)
                .default_value("7")
                .help("Stride used for strided-memtouch fake work"),
        )
        .get_matches();

    let addr: SocketAddrV4 = FromStr::from_str(matches.value_of("ADDR").unwrap()).unwrap();
    let nthreads = value_t_or_exit!(matches, "threads", u32);
    let runtime = Duration::from_secs(value_t!(matches, "runtime", u64).unwrap());
    let packets_per_second = (1.0e6 * value_t_or_exit!(matches, "mpps", f32)) as usize;
    let config = matches.value_of("config");
    let trace = matches.is_present("trace");
    let dowarmup = matches.is_present("warmup");
    let proto = match matches.value_of("protocol").unwrap() {
        "synthetic" => Protocol::Synthetic,
        "memcached" => Protocol::Memcached,
        "dns" => Protocol::Dns,
        _ => unreachable!(),
    };
    let mean = value_t_or_exit!(matches, "mean", f64);
    let distribution = match matches.value_of("distribution").unwrap() {
        "zero" => Distribution::Zero,
        "constant" => Distribution::Constant(mean as u64),
        "exponential" => Distribution::Exponential(mean),
        "bimodal1" => Distribution::Bimodal1(mean),
        "bimodal2" => Distribution::Bimodal2(mean),
        _ => unreachable!(),
    };
    let samples = value_t_or_exit!(matches, "samples", usize);
    let mode = matches.value_of("mode").unwrap();
    let backend = match mode {
        "linux-server" | "linux-client" => Backend::Linux,
        "runtime-server" | "spawner-server" | "runtime-client" | "work-bench" => Backend::Runtime,
        _ => unreachable!(),
    };
    let mut barrier_group = matches.value_of("barrier-leader").map(|leader| {
        lockstep::Group::from_hostname(
            leader,
            23232,
            value_t_or_exit!(matches, "barrier-peers", usize),
        ).unwrap()
    });

    let mut rng = rand::thread_rng();
    unsafe {
        STRIDED_MEMTOUCH_STRIDE = value_t_or_exit!(matches, "strided-stride", usize);
        STRIDED_MEMTOUCH_BUFFER = Some(
            (0..value_t_or_exit!(matches, "strided-size", usize))
                .map(|_| rng.gen())
                .collect(),
        );
    }

    match mode {
        "work-bench" => {
            let iterations = 100_000_000;
            println!("Timing {} iterations of work()", iterations);
            let start = Instant::now();
            work(iterations);
            let elapsed = duration_to_ns(start.elapsed());
            println!("Rate = {} ns/iteration", elapsed as f64 / iterations as f64);
        }
        "spawner-server" => backend.init_and_run(config, move || run_spawner_server(addr)),
        "linux-server" | "runtime-server" => backend.init_and_run(config, move || {
            let socket = backend.create_udp_connection(addr, None);
            println!("Bound to address {}", socket.local_addr());
            run_server(backend, socket, nthreads)
        }),
        "linux-client" | "runtime-client" => {
            backend.init_and_run(config, move || {
                if dowarmup {
                    match proto {
                        Protocol::Dns => {}
                        Protocol::Memcached => {
                            memcached::warmup(backend, addr, nthreads as u64);
                            println!("Warmup done");
                            return;
                        }
                        Protocol::Synthetic => for packets_per_second in (1..3).map(|i| i * 100000)
                        {
                            run_client(
                                backend,
                                addr,
                                Duration::from_secs(1),
                                packets_per_second,
                                nthreads,
                                OutputMode::Silent,
                                proto,
                                distribution,
                                &mut barrier_group,
                            );
                        },
                    }
                }

                if trace {
                    run_client(
                        backend,
                        addr,
                        runtime,
                        packets_per_second,
                        nthreads,
                        OutputMode::Trace,
                        proto,
                        distribution,
                        &mut barrier_group,
                    );
                    return;
                }

                if let Protocol::Synthetic = proto {
                    for (i, distribution) in [
                        Distribution::Constant(mean as u64),
                        Distribution::Exponential(mean),
                        Distribution::Bimodal1(mean),
                    ].iter()
                        .enumerate()
                    {
                        for j in 1..=samples {
                            run_client(
                                backend,
                                addr,
                                runtime,
                                packets_per_second * j / samples,
                                nthreads,
                                if i == 0 && j == 1 {
                                    OutputMode::IncludeRawWithHeader
                                } else {
                                    OutputMode::IncludeRaw
                                },
                                proto,
                                *distribution,
                                &mut barrier_group,
                            );
                        }
                    }
                } else {
                    run_client(
                        backend,
                        addr,
                        Duration::from_secs(3),
                        packets_per_second / samples,
                        nthreads,
                        OutputMode::Silent,
                        proto,
                        distribution,
                        &mut barrier_group,
                    );
                    for j in 1..=samples {
                        run_client(
                            backend,
                            addr,
                            runtime,
                            packets_per_second * j / samples,
                            nthreads,
                            OutputMode::IncludeRaw,
                            proto,
                            distribution,
                            &mut barrier_group,
                        );
                    }
                    if let Some(ref mut g) = barrier_group {
                        g.barrier();
                    }
                }
            });
        }
        _ => unreachable!(),
    };
}
