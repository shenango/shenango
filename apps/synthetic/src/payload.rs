use Packet;

use std::io;
use byteorder::{WriteBytesExt, ReadBytesExt, BigEndian};

pub struct Payload {
    pub work_iterations: u64,
    pub index: u64,
}

pub fn parse_response(buf: &[u8]) -> Result<usize, ()> {
    match deserialize(buf) {
        Ok(payload) => Ok(payload.index as usize),
        Err(_) => Err(()),
    }
}

pub fn create_request(i: usize, p: &mut Packet, buf: &mut Vec<u8>) {
    serialize(
        Payload {
            work_iterations: p.work_iterations,
            index: i as u64,
        },
        buf
    ).unwrap();
}

pub fn serialize(p: Payload, buf: &mut Vec<u8>) -> Result<(), io::Error>{
    buf.write_u64::<BigEndian>(p.work_iterations)?;
    buf.write_u64::<BigEndian>(p.index)?;
    return Ok(());
}

pub fn deserialize(buf: &[u8]) -> Result<Payload, io::Error> {
    let mut buf = buf;
    let p = Payload {
        work_iterations: buf.read_u64::<BigEndian>()?,
        index: buf.read_u64::<BigEndian>()?,
    };
    return Ok(p);
}
