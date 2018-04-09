
use std::io::Cursor;
use std::io::Write;

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use memcache_packet::{PacketHeader, Opcode, Magic, ResponseStatus};
use memcache_packet::parse_header_only_response;

use backend::*;

use Packet;

static NVALUES : u64 = 100000;
static PCT_SET : u64 = 10; // out of 100
// static value_size  : u32 = 0;
// static key_size    : u32 = 0;

fn set_request(key: &String, opaque: u32, buf: &mut Vec<u8>) {
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

    // Use first 32 bits of randomness to determine if this is a SET or GET req
    let low32 = packet.randomness & 0xffffffff;
    // Use high 32 bits of randomness to select the key
    let key = ((packet.randomness >> 32) % NVALUES).to_string();

    if low32 % 100 < PCT_SET {
        set_request(&key, i as u32, buf);
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
    nthreads: u64,
) {

    let perthread = (NVALUES + nthreads - 1) / nthreads;

    let mut join_handles = Vec::new();

    for i in 0..nthreads {
        join_handles.push(backend.spawn_thread(move || {
            let sock1 = Arc::new(backend.create_udp_connection("0.0.0.0:0".parse().unwrap(), Some(addr)));
            let socket = sock1.clone();
            backend.spawn_thread(move || {
                backend.sleep(Duration::from_secs(5));
                if Arc::strong_count(&socket) > 1 {
                    println!("Timing out socket");
                    socket.shutdown();
                }
            });

            for n in 0..perthread {
                let mut vec: Vec<u8> = Vec::new();
                let key = (i * perthread + n).to_string();
                set_request(&key, 0, &mut vec);

                if let Err(e) = sock1.send(&vec[..]) {
                    println!("Warmup send: {}", e);
                    break;
                }

                let mut recv_buf: Vec<u8> = vec![0; 4096];
                match sock1.recv(&mut recv_buf[..]) {
                    Ok(len) => {
                        if len < 8 {
                            continue;
                        }
                        if parse_header_only_response(&mut Cursor::new(&recv_buf[8..len])).is_err() {
                            println!("Warmup: parse response error");
                            break;
                        }
                    }
                    Err(e) => {
                        println!("Warmup receive: {}", e);
                        break;
                    },
                }
            }
        }));
    }

    for j in join_handles {
        j.join().unwrap();
    }

    return; 
}
