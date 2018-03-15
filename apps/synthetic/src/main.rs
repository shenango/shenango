#![feature(duration_extras)]
#![feature(nll)]
#![feature(test)]

#[macro_use]
extern crate clap;

extern crate bincode;
extern crate libc;
extern crate rand;
extern crate shenango;
extern crate test;
extern crate byteorder;

use std::iter;
use std::net::{SocketAddrV4, UdpSocket};
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
    sleep_us: u64,
    randomness: u32,
    target_start: Duration,
    actual_start: Option<Duration>,
    completion_time: Option<Duration>,
}

mod memcached;
mod memcache_packet;
mod memcache_error;

enum Distribution {
    Zero,
    Constant,
    Bimodal1,
    Bimodal2,
}

#[derive(Copy, Clone)]
enum Protocol {
    Synthetic,
    Memcached,
}

fn work(iterations: u64) {
    let k = 2350845.545;
    for i in 0..iterations {
        test::black_box(f64::sqrt(k * i as f64));
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

                    let _payload: Payload = bincode::deserialize(&buf[..len]).unwrap();
                    //                    backend.dummy_work(payload.sleep_us);

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
            let _payload: Payload = bincode::deserialize(buf).unwrap();
            //            Backend::Runtime.dummy_work(payload.sleep_us);
            let _ = UdpSpawner::reply(d, buf);
            UdpSpawner::release_data(d);
        }
    }

    let _s = unsafe { UdpSpawner::new(addr, echo).unwrap() };

    loop {
        shenango::sleep(Duration::from_secs(10));
    }
}

fn warmup(
    backend: Backend,
    addr: SocketAddrV4,
    nthreads: u32,
    protocol: Protocol,
) {
    match protocol {
        Protocol::Synthetic => return,
        Protocol::Memcached => memcached::warmup(backend, addr, nthreads),
    }
}

fn run_client(
    backend: Backend,
    addr: SocketAddrV4,
    runtime: Duration,
    packets_per_second: usize,
    nthreads: u32,
    trace: bool,
    protocol: Protocol,
) {

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
                    randomness: rng.gen::<u32>(),
                    target_start: Duration::from_nanos(last),
                    ..Default::default()
                });
            }
            (packets, vec![None; packets_per_thread])
        })
        .collect();

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
                        let idx = match protocol {
                            Protocol::Memcached => memcached::parse_response(&recv_buf[..len]),
                            Protocol::Synthetic => payload::parse_response(&recv_buf[..len]),
                        };
                        if idx.is_err() {
                            break;
                        }
                        receive_times[idx.unwrap() as usize] = Some(start.elapsed());
                    }
                    Err(_) => break,
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
                };

                while start.elapsed() < packet.target_start {
                    backend.thread_yield()
                }
                packet.actual_start = Some(start.elapsed());
                if socket2.send(&payload[..]).is_err() {
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
    let dropped = packets
        .iter()
        .filter(|p| p.completion_time.is_none())
        .count();
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
    assert!(!latencies.is_empty());

    let percentile = |p| {
        duration_to_ns(latencies[(latencies.len() as f32 * p / 100.0) as usize]) as f32 / 1000.0
    };
    println!(
        "{}, {}, {}, {:.1}, {:.1}, {:.1}, {:.1}, {:.1}",
        packets_per_second,
        (packets.len() - dropped) as u64 * 1000_000_000 / duration_to_ns(last_send - first_send),
        dropped,
        percentile(50.0),
        percentile(90.0),
        percentile(99.0),
        percentile(99.9),
        percentile(99.99)
    );

    if trace {
        packets.sort_by_key(|p|p.actual_start.unwrap_or(p.target_start));
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
                .possible_values(&[
                    "synthetic",
                    "memcached",
                ])
                .default_value("synthetic")
                .help("Which client protocol to speak"),
        )
        .arg(
            Arg::with_name("warmup")
                .long("warmup")
                .takes_value(false)
                .help("Run the warmup routine"),
        )
        .get_matches();

    let addr = matches.value_of("ADDR").unwrap().to_owned();
    let nthreads = value_t_or_exit!(matches, "threads", u32);
    let runtime = Duration::from_secs(value_t!(matches, "runtime", u64).unwrap());
    let packets_per_second = (1.0e6 * value_t_or_exit!(matches, "mpps", f32)) as usize;
    let config = matches.value_of("config");
    let trace = matches.is_present("trace");
    let dowarmup = matches.is_present("warmup");
    let proto = match matches.value_of("protocol").unwrap() {
        "synthetic" => Protocol::Synthetic,
        "memcached" => Protocol::Memcached,
        _ => unreachable!(),
    };

    match matches.value_of("mode").unwrap() {
        "linux-server" => {
            let socket = UdpSocket::bind(addr).unwrap();
            println!("Bound to address {}", socket.local_addr().unwrap());
            run_server(Backend::Linux, UdpConnection::Linux(socket), nthreads)
        }
        "linux-client" => {
            if dowarmup {
                warmup(Backend::Linux, FromStr::from_str(&addr).unwrap(), nthreads, proto);
                println!("Warmup done");
                return;
            }
            for packets_per_second in (1..100).map(|i| i * 10000) {
                run_client(
                    Backend::Linux,
                    FromStr::from_str(&addr).unwrap(),
                    runtime,
                    packets_per_second,
                    nthreads,
                    false,
                    proto,
                )
            }
        },
        "runtime-server" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            let addr = FromStr::from_str(&addr).unwrap();
            let socket = shenango::udp::UdpConnection::listen(addr);
            println!("Bound to address {}", socket.local_addr());
            run_server(Backend::Runtime, UdpConnection::Runtime(socket), nthreads)
        }).unwrap(),
        "runtime-client" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            if trace {
                for packets_per_second in (1..3).map(|i| i * 100000) {
                    print!("# ");
                    run_client(
                        Backend::Runtime,
                        FromStr::from_str(&addr).unwrap(),
                        Duration::from_secs(1),
                        packets_per_second,
                        nthreads,
                        false,
                        proto,
                    );
                }
                run_client(
                    Backend::Runtime,
                    FromStr::from_str(&addr).unwrap(),
                    runtime,
                    packets_per_second,
                    nthreads,
                    true,
                    proto,
                );
            } else {
                if dowarmup {
                    warmup(Backend::Runtime, FromStr::from_str(&addr).unwrap(), nthreads, proto);
                    println!("Warmup done");
                    return;
                }
                for packets_per_second in (iter::once(1).chain(1..500)).map(|i| i * 200000) {
                    run_client(
                        Backend::Runtime,
                        FromStr::from_str(&addr).unwrap(),
                        runtime,
                        packets_per_second,
                        nthreads,
                        false,
                        proto,
                    );
                    //                    shenango::sleep(Duration::from_millis(1000));
                }
            }
        }).unwrap(),
        "spawner-server" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            run_spawner_server(FromStr::from_str(&addr).unwrap())
        }).unwrap(),
        _ => unreachable!(),
    };
}
