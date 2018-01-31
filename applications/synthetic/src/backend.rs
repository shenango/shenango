use shenango;
use std;
use libc;

use std::any::Any;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::thread;

#[derive(Copy, Clone)]
pub enum Backend {
    Linux,
    Runtime,
}
impl Backend {
    pub fn create_udp_connection(
        &self,
        local_addr: SocketAddrV4,
        remote_addr: Option<SocketAddrV4>,
    ) -> UdpConnection {
        match (self, remote_addr) {
            (&Backend::Linux, None) => UdpConnection::Linux(UdpSocket::bind(local_addr).unwrap()),
            (&Backend::Runtime, None) => {
                UdpConnection::Runtime(shenango::udp::UdpConnection::listen(local_addr))
            }
            (&Backend::Linux, Some(remote_addr)) => {
                let socket = UdpSocket::bind(local_addr).unwrap();
                socket.connect(remote_addr).unwrap();
                UdpConnection::Linux(socket)
            }
            (&Backend::Runtime, Some(remote_addr)) => {
                UdpConnection::Runtime(shenango::udp::UdpConnection::dial(local_addr, remote_addr))
            }
        }
    }

    pub fn spawn_thread<T, F>(&self, f: F) -> JoinHandle<T>
    where
        T: Send,
        F: FnOnce() -> T,
        F: Send + 'static,
    {
        match *self {
            Backend::Linux => JoinHandle::Linux(thread::spawn(f)),
            Backend::Runtime => JoinHandle::Runtime(shenango::thread::spawn(f)),
        }
    }
}

pub enum UdpConnection {
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

    #[allow(unused)]
    pub fn shutdown(&self) {
        match *self {
            UdpConnection::Linux(ref s) => unsafe {
                let _ = libc::shutdown(s.as_raw_fd(), libc::SHUT_RD);
            },
            UdpConnection::Runtime(ref s) => s.shutdown(),
        }
    }
}

pub enum JoinHandle<T: Send + 'static> {
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
