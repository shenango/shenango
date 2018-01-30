#![feature(nll)]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate serde_derive;

extern crate bincode;
extern crate libc;
extern crate shenango;

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bincode::Infinite;
use clap::{App, Arg};

#[derive(Serialize, Deserialize)]
struct Payload {
    sleep_us: u64,
    client_thread: usize,
    packet_index: usize,
}

enum UdpConnection {
    Linux(UdpSocket),
    Runtime(shenango::udp::UdpConnection),
}
impl UdpConnection {
    pub fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<usize> {
        match *self {
            UdpConnection::Linux(ref s) => s.send_to(buf, addr),
            UdpConnection::Runtime(ref s) => s.write_to(buf, addr),
        }
    }
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        match *self {
            UdpConnection::Linux(ref s) => s.recv_from(buf).map(|(len, addr)| match addr {
                SocketAddr::V4(addr) => (len, addr),
                _ => unreachable!(),
            }),
            UdpConnection::Runtime(ref s) => s.read_from(buf),
        }
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            UdpConnection::Linux(ref s) => s.send(buf),
            UdpConnection::Runtime(ref s) => s.send(buf),
        }
    }
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            UdpConnection::Linux(ref s) => s.recv(buf),
            UdpConnection::Runtime(ref s) => s.recv(buf),
        }
    }

    pub fn shutdown(&self) {
        match *self {
            UdpConnection::Linux(ref s) => unsafe {
                let _ = libc::shutdown(s.as_raw_fd(), libc::SHUT_RD);
            },
            UdpConnection::Runtime(ref s) => s.shutdown(),
        }
    }

    pub fn spawn_thread<T, F>(&self, f: F) -> JoinHandle<T>
    where
        T: Send,
        F: FnOnce() -> T,
        F: Send + 'static,
    {
        match *self {
            UdpConnection::Linux(_) => JoinHandle::Linux(thread::spawn(f)),
            UdpConnection::Runtime(_) => JoinHandle::Runtime(shenango::thread::spawn(f)),
        }
    }
}
enum JoinHandle<T: Send + 'static> {
    Linux(std::thread::JoinHandle<T>),
    Runtime(shenango::thread::JoinHandle<T>),
}
impl<T: Send + 'static> JoinHandle<T> {
    pub fn join(self) -> Result<T, Box<Any + Send + 'static>> {
        match self {
            JoinHandle::Linux(j) => j.join(),
            JoinHandle::Runtime(j) => j.join(),
        }
    }
}

fn duration_to_ns(duration: Duration) -> u64 {
    (duration.as_secs() * 1000_000_000 + duration.subsec_nanos() as u64)
}

fn run_server(socket: UdpConnection, nthreads: u32) {
    let socket = Arc::new(socket);
    let join_handles: Vec<_> = (0..nthreads)
        .map(|_| {
            let socket2 = socket.clone();
            socket.spawn_thread(move || {
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

fn run_client(socket: UdpConnection, runtime: Duration, nthreads: u32) {
    let socket = Arc::new(socket);
    let start = Instant::now();

    let socket2 = socket.clone();
    let recv_thread = socket.spawn_thread(move || {
        let mut receive_times = Vec::new();
        let mut recv_buf = vec![0; 4096];
        while let Ok(len) = socket2.recv(&mut recv_buf[..]) {
            if len == 0 {
                break;
            }

            if let Some(payload) = bincode::deserialize::<Payload>(&recv_buf[..len]).ok() {
                receive_times.push((
                    (payload.client_thread, payload.packet_index),
                    start.elapsed(),
                ));
            }
        }
        receive_times
    });

    let mut send_threads = Vec::new();
    for i in 0..nthreads {
        let socket2 = socket.clone();
        send_threads.push(socket.spawn_thread(move || {
            let mut send_times = Vec::new();
            while start.elapsed() < runtime {
                let payload = bincode::serialize(
                    &Payload {
                        sleep_us: 0,
                        client_thread: i as usize,
                        packet_index: send_times.len(),
                    },
                    Infinite,
                ).unwrap();
                send_times.push(start.elapsed());
                socket2.send(&payload[..]).unwrap();
            }
            send_times
        }));
    }

    let send_times: Vec<Vec<Duration>> = send_threads
        .into_iter()
        .map(|j| j.join().unwrap())
        .collect();

    thread::sleep(Duration::from_millis(500));

    socket.shutdown();
    let receive_times = recv_thread.join().unwrap();
    let receive_times: HashMap<_, Duration> = receive_times.into_iter().collect();

    let total_packets = send_times.iter().map(|s| s.len()).sum::<usize>();
    let dropped = total_packets - receive_times.len();
    let mut latencies: Vec<_> = send_times
        .into_iter()
        .enumerate()
        .flat_map(|(thread, send_times): (usize, _)| {
            send_times
                .into_iter()
                .enumerate()
                .filter_map(|(index, start)| {
                    receive_times
                        .get(&(thread, index))
                        .cloned()
                        .map(|end| end - start)
                })
                .collect::<Vec<_>>()
                .into_iter()
        })
        .collect();
    latencies.sort();

    if latencies.is_empty() {
        println!("All {} packets were dropped", dropped);
    } else {
        let min = latencies.iter().min().unwrap().clone();
        let max = latencies.iter().max().unwrap().clone();
        let median = latencies.get(latencies.len() / 2).unwrap().clone();
        println!(
            "min:    {:.2} us\nmedian: {:.2} us\nmax:    {:.2} us\n(Plus {}/{} = {}% dropped)",
            duration_to_ns(min) as f32 / 1000.0,
            duration_to_ns(median) as f32 / 1000.0,
            duration_to_ns(max) as f32 / 1000.0,
            dropped,
            latencies.len(),
            (dropped * 100) / total_packets
        );
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
            Arg::with_name("config")
                .short("c")
                .long("config")
                .takes_value(true),
        )
        .get_matches();

    let addr = matches.value_of("ADDR").unwrap().to_owned();
    let nthreads = value_t_or_exit!(matches, "threads", u32);
    let runtime = Duration::from_secs(value_t!(matches, "runtime", u64).unwrap());
    let config = matches.value_of("config");

    match matches.value_of("mode").unwrap() {
        "linux-server" => {
            let socket = UdpSocket::bind(addr).unwrap();
            println!("Bound to address {}", socket.local_addr().unwrap());
            run_server(UdpConnection::Linux(socket), nthreads)
        }
        "linux-client" => {
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.connect(addr).unwrap();
            run_client(UdpConnection::Linux(socket), runtime, nthreads)
        }
        "runtime-server" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            let addr = FromStr::from_str(&addr).unwrap();
            let socket = shenango::udp::UdpConnection::listen(addr);
            println!("Bound to address {}", socket.local_addr());
            run_server(UdpConnection::Runtime(socket), nthreads)
        }).unwrap(),
        "runtime-client" => shenango::runtime_init(config.unwrap().to_owned(), move || {
            let remote_addr = FromStr::from_str(&addr).unwrap();
            let local_addr = FromStr::from_str("0.0.0.0:0").unwrap();
            let socket = shenango::udp::UdpConnection::dial(local_addr, remote_addr);
            run_client(UdpConnection::Runtime(socket), runtime, nthreads)
        }).unwrap(),
        _ => unreachable!(),
    };
}
