#![feature(nll)]
#![feature(duration_extras)]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate serde_derive;

extern crate bincode;
extern crate libc;
extern crate rand;
extern crate shenango;

use std::net::{SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bincode::Infinite;
use clap::{App, Arg};
use rand::distributions::{Exp, IndependentSample};

mod backend;
use backend::*;

#[derive(Serialize, Deserialize)]
struct Payload {
    sleep_us: u64,
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
                    shenango::delay_us(payload.sleep_us);

                    socket2.send_to(&buf[..len], remote_addr).unwrap();
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
    nthreads: u32,
    trace: bool,
) {
    #[derive(Default)]
    struct Packet {
        sleep_us: u64,
        target_start: Duration,
        actual_start: Option<Duration>,
        completion_time: Option<Duration>,
    }

    let packets_per_thread =
        duration_to_ns(runtime) as usize * packets_per_second / (1000_000_000 * nthreads as usize);
    let ns_per_packet = nthreads as usize * 1000_000_000 / (packets_per_second);

    let exp = Exp::new(1.0 / ns_per_packet as f64);
    let mut rng = rand::thread_rng();
    let packet_schedules: Vec<Vec<Packet>> = (0..nthreads)
        .map(|_| {
            let mut last = 0;
            let mut packets = Vec::with_capacity(packets_per_thread);
            for _ in 0..packets_per_thread {
                last += exp.ind_sample(&mut rng) as u64;
                packets.push(Packet {
                    target_start: Duration::from_nanos(last),
                    ..Default::default()
                });
            }
            packets
        })
        .collect();

    let start = Instant::now();

    let mut send_threads = Vec::new();
    let mut receive_threads = Vec::new();
    for mut packets in packet_schedules {
        let socket =
            Arc::new(backend.create_udp_connection("0.0.0.0:0".parse().unwrap(), Some(addr)));
        let socket2 = socket.clone();

        let mut receive_times = vec![None; packets.len()];
        receive_threads.push(backend.spawn_thread(move || {
            let mut recv_buf = vec![0; 4096];
            for i in 0..receive_times.len() {
                match socket.recv(&mut recv_buf[..]) {
                    Ok(len) => {
                        if let Ok(_payload) = bincode::deserialize::<Payload>(&recv_buf[..len]) {
                            receive_times[i] = Some(start.elapsed());
                        }
                    }
                    Err(_) => break,
                }
            }
            receive_times
        }));
        send_threads.push(backend.spawn_thread(move || {
            for packet in packets.iter_mut() {
                let payload = bincode::serialize(
                    &Payload {
                        sleep_us: packet.sleep_us,
                    },
                    Infinite,
                ).unwrap();

                while start.elapsed() < packet.target_start {
                    shenango::cpu_relax()
                }
                packet.actual_start = Some(start.elapsed());
                socket2.send(&payload[..]).unwrap();
            }

            // If the receive thread is still running 500 ms from now, then stop it by triggering a
            // shutdown on the socket.
            backend.spawn_thread(move || {
                backend.sleep(Duration::from_millis(500));
                if Arc::strong_count(&socket2) > 1 {
                    socket2.shutdown();
                }
            });

            packets
        }))
    }

    let packets: Vec<_> = send_threads
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
        packets_per_second as u64 * 1000_000_000 / duration_to_ns(runtime),
        (packets.len() - dropped) as u64 * 1000_000_000 / duration_to_ns(last_send),
        dropped,
        percentile(50.0),
        percentile(90.0),
        percentile(99.0),
        percentile(99.9),
        percentile(99.99)
    );

    if trace {
        for p in packets {
            if let Some(completion_time) = p.completion_time {
                let actual_start = p.actual_start.unwrap();
                println!(
                    "{}, {}, {}",
                    duration_to_ns(actual_start),
                    duration_to_ns(actual_start - p.target_start),
                    duration_to_ns(completion_time - actual_start)
                )
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
                ])
                .required(true)
                .requires_ifs(&[("runtime-server", "config"), ("runtime-client", "config")])
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
        .get_matches();

    let addr = matches.value_of("ADDR").unwrap().to_owned();
    let nthreads = value_t_or_exit!(matches, "threads", u32);
    let runtime = Duration::from_secs(value_t!(matches, "runtime", u64).unwrap());
    let packets_per_second = (1.0e6 * value_t_or_exit!(matches, "mpps", f32)) as usize;
    let config = matches.value_of("config");
    let trace = matches.is_present("trace");

    match matches.value_of("mode").unwrap() {
        "linux-server" => {
            let socket = UdpSocket::bind(addr).unwrap();
            println!("Bound to address {}", socket.local_addr().unwrap());
            run_server(Backend::Linux, UdpConnection::Linux(socket), nthreads)
        }
        "linux-client" => for packets_per_second in (1..100).map(|i| i * 10000) {
            run_client(
                Backend::Linux,
                FromStr::from_str(&addr).unwrap(),
                runtime,
                packets_per_second,
                nthreads,
                false
            )
        },
        "runtime-server" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            let addr = FromStr::from_str(&addr).unwrap();
            let socket = shenango::udp::UdpConnection::listen(addr);
            println!("Bound to address {}", socket.local_addr());
            run_server(Backend::Runtime, UdpConnection::Runtime(socket), nthreads)
        }).unwrap(),
        "runtime-client" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            if trace {
                run_client(
                    Backend::Runtime,
                    FromStr::from_str(&addr).unwrap(),
                    runtime,
                    packets_per_second,
                    nthreads,
                    true,
                );
            } else {
                for packets_per_second in (1..500).map(|i| i * 20000) {
                    run_client(
                        Backend::Runtime,
                        FromStr::from_str(&addr).unwrap(),
                        runtime,
                        packets_per_second,
                        nthreads,
                        false,
                    );
                    shenango::sleep(Duration::from_millis(1000));
                }
            }
        }).unwrap(),
        _ => unreachable!(),
    };
}
