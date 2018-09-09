#![feature(nll)]
#![feature(test)]
#[macro_use]
extern crate clap;

extern crate byteorder;
extern crate dns_parser;
extern crate libc;
extern crate lockstep;
extern crate net2;
extern crate rand;
extern crate shenango;
extern crate test;

use std::io;
use std::io::{Write, ErrorKind};
use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::slice;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::f32::INFINITY;

use clap::{App, Arg};
use rand::distributions::{Exp, IndependentSample};
use rand::Rng;
use shenango::udp::UdpSpawner;

mod backend;
use backend::*;

mod payload;
use payload::{Payload, SyntheticProtocol};

#[derive(Default)]
pub struct Packet {
    work_iterations: u64,
    randomness: u64,
    target_start: Duration,
    actual_start: Option<Duration>,
    completion_time: Option<Duration>,
}

mod memcached;
use memcached::MemcachedProtocol;

mod dns;
use dns::DnsProtocol;

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

arg_enum!{
#[derive(Copy, Clone)]
pub enum Transport {
    Udp,
    Tcp,
}}

arg_enum!{
#[derive(Copy, Clone)]
enum Protocol {
    Synthetic,
    Memcached,
    Dns,
}}

impl Protocol {
    fn gen_request(
        &self,
        i: usize,
        p: &Packet,
        buf: &mut Vec<u8>,
        tport: Transport
    ) {
        match *self {
            Protocol::Memcached =>
                MemcachedProtocol::gen_request(i, p, buf, tport),
            Protocol::Synthetic =>
                SyntheticProtocol::gen_request(i, p, buf, tport),
            Protocol::Dns =>
                DnsProtocol::gen_request(i, p, buf, tport),
        }
    }

    fn read_response(
        &self,
        sock: &Connection,
        tport: Transport,
        scratch: &mut [u8]
    ) -> io::Result<usize> {
        match *self {
           Protocol::Synthetic =>
                SyntheticProtocol::read_response(sock, tport, scratch),
            Protocol::Memcached =>
                MemcachedProtocol::read_response(sock, tport, scratch),
            Protocol::Dns =>
                DnsProtocol::read_response(sock, tport, scratch)
        }
    }
}

arg_enum!{
#[derive(Copy, Clone)]
enum OutputMode {
    Silent,
    Normal,
    Buckets,
    Trace
}}

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

fn run_linux_udp_server(backend: Backend, addr: SocketAddrV4, nthreads: usize) {
    let join_handles: Vec<_> = (0..nthreads)
        .map(|_| {
            backend.spawn_thread(move || {
                let socket = backend.create_udp_connection(addr, None).unwrap();
                println!("Bound to address {}", socket.local_addr());
                let mut buf = vec![0; 4096];
                loop {
                    let (len, remote_addr) = socket.recv_from(&mut buf[..]).unwrap();
                    let payload = Payload::deserialize(&mut &buf[..len]).unwrap();
                    work(payload.work_iterations);
                    socket.send_to(&buf[..len], remote_addr).unwrap();
                }
            })
        })
        .collect();

    for j in join_handles {
        j.join().unwrap();
    }
}



fn socket_worker(socket: &mut Connection) {
    let mut v = vec![0; 4096];
    #[inline(always)]
    fn r(socket: &mut Connection, v: &mut Vec<u8>) -> io::Result<()> {
        v.clear();
        let payload = Payload::deserialize(socket)?;
        work(payload.work_iterations);
        payload.serialize_into(v)?;
        Ok(socket.write_all(&v [..])?)
    };
    loop {
        if let Err(e) = r(socket, &mut v) {
            match e.raw_os_error() {
              Some(-104) | Some(104) => break,
              _ => {},
            }
            if e.kind() != ErrorKind::UnexpectedEof {
                println!("Receive thread: {}", e);
            }
            break;
        }
    }
}

fn run_tcp_server(backend: Backend, addr: SocketAddrV4) {
    let tcpq = backend.create_tcp_listener(addr).unwrap();
    println!("Bound to address {}", addr);
    loop {
        match tcpq.accept() {
            Ok(mut c) => {
                backend.spawn_thread(move || socket_worker(&mut c));
            },
            Err(e) => {
                println!("Listener: {}", e);
            }
        }
    }
}

fn run_spawner_server(addr: SocketAddrV4) {
    extern "C" fn echo(d: *mut shenango::ffi::udp_spawn_data) {
        unsafe {
            let buf = slice::from_raw_parts((*d).buf as *mut u8, (*d).len);
            let payload = Payload::deserialize(&mut &buf[..]).unwrap();
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

fn run_memcached_preload(
    backend: Backend,
    tport: Transport,
    addr: SocketAddrV4,
    nthreads: usize,
) {
    let perthread = (memcached::NVALUES as usize + nthreads - 1) / nthreads;
    let join_handles: Vec<JoinHandle<_>> = (0..nthreads)
        .map(|i| {
            backend.spawn_thread(move || {
                let sock1 = Arc::new(
                    match tport {
                        Transport::Tcp =>
                            backend.create_tcp_connection(addr).unwrap(),
                        Transport::Udp =>
                            backend.create_udp_connection(
                                "0.0.0.0:0".parse().unwrap(),
                                Some(addr)
                            ).unwrap(),
                    }
                );
                let socket = sock1.clone();
                backend.spawn_thread(move || {
                    backend.sleep(Duration::from_secs(20));
                    if Arc::strong_count(&socket) > 1 {
                        println!("Timing out socket");
                        socket.shutdown();
                    }
                });

                let mut vec_s: Vec<u8> = Vec::with_capacity(4096);
                let mut vec_r: Vec<u8> = vec![0; 4096];
                for n in 0..perthread {
                    vec_s.clear();
                    MemcachedProtocol::set_request((i * perthread + n) as u64, 0, &mut vec_s, tport);

                    if let Err(e) = (&*sock1).write_all(&vec_s[..]) {
                        println!("Preload send ({}/{}): {}", n, perthread, e);
                        break;
                    }

                    if let Err(e) = MemcachedProtocol::read_response(&sock1, tport, &mut vec_r[..]) {
                        println!("preload receive ({}/{}): {}", n, perthread, e);
                        break;
                    }

                }
            })
        })
        .collect();

    for j in join_handles {
        j.join().unwrap();
    }
}

fn run_client(
    backend: Backend,
    addr: SocketAddrV4,
    runtime: Duration,
    packets_per_second: usize,
    nthreads: usize,
    output: OutputMode,
    protocol: Protocol,
    tport: Transport,
    distribution: Distribution,
    barrier_group: &mut Option<lockstep::Group>,
) -> bool {
    let packets_per_thread =
        duration_to_ns(runtime) as usize * packets_per_second / (1000_000_000 * nthreads);
    let ns_per_packet = nthreads * 1000_000_000 / packets_per_second;

    let exp = Exp::new(1.0 / ns_per_packet as f64);
    let mut rng = rand::thread_rng();
    let packet_schedules: Vec<(Vec<Packet>, Vec<Option<Duration>>, Connection)> = (0..nthreads)
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
            let socket = match tport {
                Transport::Tcp =>
                    backend.create_tcp_connection(addr).unwrap(),
                Transport::Udp =>
                    backend.create_udp_connection(
                        "0.0.0.0:0".parse().unwrap(),
                        Some(addr)
                    ).unwrap(),
            };
            (packets, vec![None; packets_per_thread], socket)
        })
        .collect();

    if let Some(ref mut g) = *barrier_group {
        g.barrier();
    }
    let start_unix = SystemTime::now();
    let start = Instant::now();

    let mut send_threads = Vec::new();
    let mut receive_threads = Vec::new();
    for (mut packets, mut receive_times, socket) in packet_schedules {

        let socket = Arc::new(socket);
        let socket2 = socket.clone();

        receive_threads.push(backend.spawn_thread(move || {
            let mut recv_buf = vec![0; 4096];
            for _ in 0..receive_times.len() {
                match protocol.read_response(&socket, tport, &mut recv_buf[..]) {
                    Ok(idx) => receive_times[idx] = Some(start.elapsed()),
                    Err(e) => {
                        match e.raw_os_error() {
                            Some(-103) | Some(-104) => break,
                            _ => (),
                        }
                        if e.kind() != ErrorKind::UnexpectedEof {
                            println!("Receive thread: {}", e);
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
            let timer = backend.spawn_thread(move || {
                backend.sleep(runtime + Duration::from_millis(500));
                if Arc::strong_count(&socket) > 1 {
                    socket.shutdown();
                }
            });

            let mut payload = Vec::with_capacity(4096);
            for (i, packet) in packets.iter_mut().enumerate() {
                payload.clear();
                protocol.gen_request(i, packet, &mut payload, tport);

                let t = start.elapsed();
                if t < packet.target_start {
                    backend.sleep(packet.target_start - t);
                }
                if start.elapsed() > packet.target_start + Duration::from_micros(5) {
                    continue;
                }

                packet.actual_start = Some(start.elapsed());
                if let Err(e) = (&*socket2).write_all(&payload[..]) {
                    packet.actual_start = None;
                    match e.raw_os_error() {
                        Some(-105) => {
                            backend.thread_yield();
                            continue;
                        }
                        Some(-32) | Some(-103) | Some(-104) => {}
                        _ => println!("Send thread ({}/{}): {}", i, packets.len(), e),
                    }
                    break;
                }
            }
            timer.join().unwrap();

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
            OutputMode::Normal
            | OutputMode::Buckets
            | OutputMode::Trace => {
                println!(
                    "{}, {}, 0, {}, {}, {}",
                    distribution.name(),
                    packets_per_second,
                    dropped,
                    never_sent,
                    start_unix.duration_since(UNIX_EPOCH).unwrap().as_secs()
                );
            }
        }
        return false;
    }

    if let OutputMode::Silent = output {
        return true;
    }

    let first_send = packets.iter().filter_map(|p| p.actual_start).min().unwrap();
    let last_send = packets.iter().filter_map(|p| p.actual_start).max().unwrap();

    let mut latencies: Vec<_> = packets
        .iter()
        .filter_map(|p| match (p.actual_start, p.completion_time) {
            (Some(ref start), Some(ref end)) => Some(*end - *start),
            _ => None,
        })
        .collect();
    latencies.sort();


    match output {
        OutputMode::Silent => {}
        OutputMode::Normal
        | OutputMode::Buckets => {
            let percentile = |p| {
                let idx = ((packets.len() - never_sent) as f32 * p / 100.0) as usize;
                if idx >= latencies.len() {
                    return INFINITY;
                }
                duration_to_ns(latencies[idx]) as f32
                    / 1000.0
            };

            println!(
                "{}, {}, {}, {}, {}, {:.1}, {:.1}, {:.1}, {:.1}, {:.1}, {}",
                distribution.name(),
                (packets.len() - never_sent) as u64 * 1000_000_000 / duration_to_ns(last_send - first_send),
                latencies.len() as u64 * 1000_000_000 / duration_to_ns(last_send - first_send),
                dropped,
                never_sent,
                percentile(50.0),
                percentile(90.0),
                percentile(99.0),
                percentile(99.9),
                percentile(99.99),
                start_unix.duration_since(UNIX_EPOCH).unwrap().as_secs()
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
                        duration_to_ns(actual_start) as i64 - duration_to_ns(p.target_start) as i64,
                        duration_to_ns(completion_time - actual_start)
                    )
                } else if p.actual_start.is_some() {
                    let actual_start = p.actual_start.unwrap();
                    println!(
                        "{} {} -1",
                        duration_to_ns(actual_start),
                        duration_to_ns(actual_start) as i64 - duration_to_ns(p.target_start) as i64,
                    )
                } else {
                    println!("{} -1 -1", duration_to_ns(p.target_start))
                }
            }
        }
    }
    if let OutputMode::Buckets = output {
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
                    "runtime-client",
                    "spawner-server",
                    "work-bench",
                    "memcached-preload",
                ])
                .required(true)
                .requires_ifs(&[
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
            Arg::with_name("protocol")
                .short("p")
                .long("protocol")
                .value_name("PROTOCOL")
                .possible_values(&["synthetic", "memcached", "dns"])
                .default_value("synthetic")
                .help("Server protocol"),
        )
        .arg(
            Arg::with_name("warmup")
                .long("warmup")
                .takes_value(false)
                .help("Run the warmup routine"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("output mode")
                .possible_values(&["silent", "normal", "buckets", "trace"])
                .default_value("normal")
                .help("How to display loadgen results"),
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
        .arg(
            Arg::with_name("transport")
                .long("transport")
                .takes_value(true)
                .default_value("udp")
                .help("udp or tcp"),
        )
        .get_matches();

    let addr: SocketAddrV4 = FromStr::from_str(matches.value_of("ADDR").unwrap()).unwrap();
    let nthreads = value_t_or_exit!(matches, "threads", usize);
    let runtime = Duration::from_secs(value_t!(matches, "runtime", u64).unwrap());
    let packets_per_second = (1.0e6 * value_t_or_exit!(matches, "mpps", f32)) as usize;
    let config = matches.value_of("config");
    let dowarmup = matches.is_present("warmup");
    let proto = value_t_or_exit!(matches, "protocol", Protocol);
    let output = value_t_or_exit!(matches, "output", OutputMode);
    let tport = value_t_or_exit!(matches, "transport", Transport);
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
        "linux-server" | "linux-client" | "memcached-preload" => Backend::Linux,
        "spawner-server" | "runtime-client" | "work-bench" => Backend::Runtime,
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
        "memcached-preload" => {
            backend.init_and_run(config, move || {
                run_memcached_preload(backend, tport, addr, nthreads);
                println!("Warmup done");
            })
        },
        "spawner-server" => match tport {
            Transport::Udp => backend.init_and_run(config, move || run_spawner_server(addr)),
            Transport::Tcp => backend.init_and_run(config, move || run_tcp_server(backend, addr)),
        },
        "linux-server" => match tport {
            Transport::Udp => backend.init_and_run(config, move || run_linux_udp_server(backend, addr, nthreads)),
            Transport::Tcp => backend.init_and_run(config, move || run_tcp_server(backend, addr)),
        },
        "linux-client" | "runtime-client" => {
            backend.init_and_run(config, move || {
                println!("Distribution, Target, Actual, Dropped, Never Sent, Median, 90th, 99th, 99.9th, 99.99th, Start");
                if dowarmup {
                    for packets_per_second in (1..3).map(|i| i * 100000) {
                        run_client(
                            backend,
                            addr,
                            Duration::from_secs(1),
                            packets_per_second,
                            nthreads,
                            OutputMode::Silent,
                            proto,
                            tport,
                            distribution,
                            &mut barrier_group,
                        );
                    }
                }
                for j in 1..=samples {
                    run_client(
                        backend,
                        addr,
                        runtime,
                        packets_per_second * j / samples,
                        nthreads,
                        output,
                        proto,
                        tport,
                        distribution,
                        &mut barrier_group,
                    );
                }
                if let Some(ref mut g) = barrier_group {
                    g.barrier();
                }
            });
        }
        _ => unreachable!(),
    };
}
