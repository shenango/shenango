
use std::io::Cursor;
use std::io::Write;

use std::net::SocketAddrV4;
use std::sync::Arc;

use memcache_packet::{PacketHeader, Opcode, Magic, ResponseStatus};
use memcache_packet::parse_header_only_response;

use backend::*;

use Packet;

pub const NVALUES : u32 = 2000000;

pub fn create_request(i: usize, packet: &mut Packet, buf: &mut Vec<u8>) {
    let key = (packet.randomness % NVALUES).to_string();

    let request_header = PacketHeader {
        magic: Magic::Request as u8,
        opcode: Opcode::Get as u8,
        key_length: key.len() as u16,
        total_body_length: key.len() as u32,
        opaque: i as u32,
        ..Default::default()
    };
    request_header.write(buf).unwrap();
    buf.write_all(key.as_bytes()).unwrap();
}

pub fn parse_response(buf: &[u8]) -> Result<usize, ()> {
    if buf.len() < 8 {
        return Err(());
    }
    match PacketHeader::read(&mut Cursor::new(buf)) {
        Ok(hdr) => {
            if hdr.vbucket_id_or_status != ResponseStatus::NoError as u16 {
                return Err(());
            }
            return Ok(hdr.opaque as usize);
        },
        Err(_) => Err(()),
    }
}

pub fn warmup(
    backend: Backend,
    addr: SocketAddrV4,
    nthreads: u32,
) {

    let perthread = (NVALUES + nthreads - 1) / nthreads;

    let mut join_handles = Vec::new();

    for i in 0..nthreads {
        join_handles.push(backend.spawn_thread(move || {
            let sock1 = Arc::new(backend.create_udp_connection("0.0.0.0:0".parse().unwrap(), Some(addr)));
            for n in 0..perthread {
                let mut vec: Vec<u8> = Vec::new();
                let key = (i * perthread + n).to_string();
                let request_header = PacketHeader {
                    magic: Magic::Request as u8,
                    opcode: Opcode::Set as u8,
                    key_length: key.len() as u16,
                    extras_length: 8,
                    total_body_length: (8 + key.len() + key.len()) as u32,
                    ..Default::default()
                };
                request_header.write(&mut vec).unwrap();

                for _ in 0..8 {
                    vec.push(0 as u8);
                }

                vec.write_all(key.as_bytes()).unwrap();
                vec.write_all(key.as_bytes()).unwrap();

                if sock1.send(&vec[..]).is_err() {
                    break;
                }

                let mut recv_buf: Vec<u8> = vec![0; 4096];
                match sock1.recv(&mut recv_buf[..]) {
                    Ok(len) => {
                        if parse_header_only_response(&mut Cursor::new(&recv_buf[8..len])).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            i
        }));
    }

    for j in join_handles {
        j.join().unwrap();
    }

    return; 
}
