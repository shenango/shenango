use std::io::{self, Read, Write};
use std::ptr;
use std::net::SocketAddrV4;

use byteorder::{ByteOrder, NetworkEndian};

use super::*;

fn isize_to_result(i: isize) -> io::Result<usize> {
    if i >= 0 {
        Ok(i as usize)
    } else {
        Err(io::Error::from_raw_os_error(i as i32))
    }
}

pub struct UdpConnection(*mut ffi::udpconn_t);
impl UdpConnection {
    pub fn dial(local_addr: SocketAddrV4, remote_addr: SocketAddrV4) -> Self {
        let laddr = ffi::udpaddr {
            ip: NetworkEndian::read_u32(&local_addr.ip().octets()),
            port: local_addr.port(),
        };
        let raddr = ffi::udpaddr {
            ip: NetworkEndian::read_u32(&remote_addr.ip().octets()),
            port: remote_addr.port(),
        };

        let mut conn = ptr::null_mut();
        unsafe { ffi::udp_dial(laddr, raddr, &mut conn as *mut _) };
        UdpConnection(conn)
    }

    pub fn listen(local_addr: SocketAddrV4) -> Self {
        let laddr = ffi::udpaddr {
            ip: NetworkEndian::read_u32(&local_addr.ip().octets()),
            port: local_addr.port(),
        };
        let mut conn = ptr::null_mut();
        unsafe { ffi::udp_listen(laddr, &mut conn as *mut _) };
        UdpConnection(conn)
    }

    pub fn set_buffers(&self, read_mbufs: u32, write_mbufs: u32) -> Result<(), i32> {
        convert_error(unsafe {
            ffi::udp_set_buffers(self.0, read_mbufs as c_int, write_mbufs as c_int)
        })
    }

    pub fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let mut raddr = ffi::udpaddr { ip: 0, port: 0 };
        isize_to_result(unsafe {
            ffi::udp_read_from(
                self.0,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut raddr as *mut _,
            )
        }).map(|u| (u, SocketAddrV4::new(raddr.ip.into(), raddr.port)))
    }

    pub fn write_to(&self, buf: &[u8], remote_addr: SocketAddrV4) -> io::Result<usize> {
        let mut raddr = ffi::udpaddr {
            ip: NetworkEndian::read_u32(&remote_addr.ip().octets()),
            port: remote_addr.port(),
        };
        isize_to_result(unsafe {
            ffi::udp_write_to(
                self.0,
                buf.as_ptr() as *const c_void as *mut c_void,
                buf.len(),
                &mut raddr as *mut _,
            )
        })
    }

    /// Same as read, but doesn't take a &mut self.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        isize_to_result(unsafe {
            ffi::udp_read(self.0, buf.as_mut_ptr() as *mut c_void, buf.len())
        })
    }
    /// Same as write, but doesn't take a &mut self.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        isize_to_result(unsafe {
            ffi::udp_write(self.0, buf.as_ptr() as *const c_void, buf.len())
        })
    }


    pub fn local_addr(&self) -> SocketAddrV4 {
        let local_addr = unsafe { ffi::udp_local_addr(self.0) };
        SocketAddrV4::new(local_addr.ip.into(), local_addr.port)
    }

    pub fn remote_addr(&self) -> SocketAddrV4 {
        let remote_addr = unsafe { ffi::udp_remote_addr(self.0) };
        SocketAddrV4::new(remote_addr.ip.into(), remote_addr.port)
    }

    pub fn shutdown(&self) {
        unsafe { ffi::udp_shutdown(self.0) }
    }
}

impl Read for UdpConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        isize_to_result(unsafe {
            ffi::udp_read(self.0, buf.as_mut_ptr() as *mut c_void, buf.len())
        })
    }
}

impl Write for UdpConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        isize_to_result(unsafe {
            ffi::udp_write(self.0, buf.as_ptr() as *const c_void, buf.len())
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for UdpConnection {
    fn drop(&mut self) {
        unsafe { ffi::udp_close(self.0) }
    }
}

unsafe impl Send for UdpConnection {}
unsafe impl Sync for UdpConnection {}
