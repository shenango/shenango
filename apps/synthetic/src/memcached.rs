
use std::io::Cursor;
use std::io::Write;

use std::net::SocketAddrV4;
use std::sync::Arc;

use memcache_packet::{PacketHeader, Opcode, Magic, ResponseStatus};
use memcache_packet::parse_header_only_response;

use backend::*;

use Packet;

pub const NVALUES : u32 = 2000000;

fn set_request(keyidx: u32, opaque: u32, buf: &mut Vec<u8>) {
    let key = keyidx.to_string();
    let request_header = PacketHeader {
        magic: Magic::Request as u8,
        opcode: Opcode::Set as u8,
        key_length: key.len() as u16,
        extras_length: 8,
        total_body_length: (8 + key.len() + key.len()) as u32,
        opaque: opaque,
        ..Default::default()
    };
    request_header.write(buf).unwrap();

    for _ in 0..8 {
        buf.push(0 as u8);
    }

    buf.write_all(key.as_bytes()).unwrap();
    buf.write_all(key.as_bytes()).unwrap();
}

pub fn create_request(i: usize, packet: &Packet, buf: &mut Vec<u8>) {
    let key = (packet.randomness % NVALUES).to_string();

    if i % 10 == 1 {
        set_request(packet.randomness % NVALUES, i as u32, buf);
        return;
    }

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
    let (_, l) = buf.split_at(8);
    match PacketHeader::read(&mut Cursor::new(l)) {
        Ok(hdr) => {
            if hdr.vbucket_id_or_status != ResponseStatus::NoError as u16 {
                println!("Not NoError {}", hdr.vbucket_id_or_status);
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
                set_request(i * perthread + n, 0, &mut vec);

                if sock1.send(&vec[..]).is_err() {
                    println!("Warmup: Send error");
                    break;
                }

                let mut recv_buf: Vec<u8> = vec![0; 4096];
                match sock1.recv(&mut recv_buf[..]) {
                    Ok(len) => {
                        if parse_header_only_response(&mut Cursor::new(&recv_buf[8..len])).is_err() {
                            println!("Warmup: parse response error");
                            break;
                        }
                    }
                    Err(_) => {
                        println!("Warmup: receive error");
                        break;
                    },
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
