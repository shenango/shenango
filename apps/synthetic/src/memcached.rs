use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Error, ErrorKind, Read};

use Connection;
use Packet;
use Transport;

/** Packet code from https://github.com/aisk/rust-memcache **/

#[allow(dead_code)]
enum Opcode {
    Get = 0x00,
    Set = 0x01,
    Add = 0x02,
    Replace = 0x03,
    Delete = 0x04,
    Increment = 0x05,
    Decrement = 0x06,
    Flush = 0x08,
    Noop = 0x0a,
    Version = 0x0b,
    GetKQ = 0x0d,
    Append = 0x0e,
    Prepend = 0x0f,
    Touch = 0x1c,
}

enum Magic {
    Request = 0x80,
    Response = 0x81,
}

#[allow(dead_code)]
enum ResponseStatus {
    NoError = 0x00,
    KeyNotFound = 0x01,
    KeyExists = 0x02,
    ValueTooLarge = 0x03,
    InvalidArguments = 0x04,
}

#[derive(Debug, Default)]
struct PacketHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_length: u16,
    pub extras_length: u8,
    pub data_type: u8,
    pub vbucket_id_or_status: u16,
    pub total_body_length: u32,
    pub opaque: u32,
    pub cas: u64,
}

impl PacketHeader {
    fn write<W: io::Write>(self, writer: &mut W) -> io::Result<()> {
        writer.write_u8(self.magic)?;
        writer.write_u8(self.opcode)?;
        writer.write_u16::<BigEndian>(self.key_length)?;
        writer.write_u8(self.extras_length)?;
        writer.write_u8(self.data_type)?;
        writer.write_u16::<BigEndian>(self.vbucket_id_or_status)?;
        writer.write_u32::<BigEndian>(self.total_body_length)?;
        writer.write_u32::<BigEndian>(self.opaque)?;
        writer.write_u64::<BigEndian>(self.cas)?;
        return Ok(());
    }

    fn read<R: io::Read>(reader: &mut R) -> io::Result<PacketHeader> {
        let magic = reader.read_u8()?;
        if magic != Magic::Response as u8 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Bad magic number in response header: {}", magic),
            ));
        }
        let header = PacketHeader {
            magic: magic,
            opcode: reader.read_u8()?,
            key_length: reader.read_u16::<BigEndian>()?,
            extras_length: reader.read_u8()?,
            data_type: reader.read_u8()?,
            vbucket_id_or_status: reader.read_u16::<BigEndian>()?,
            total_body_length: reader.read_u32::<BigEndian>()?,
            opaque: reader.read_u32::<BigEndian>()?,
            cas: reader.read_u64::<BigEndian>()?,
        };
        return Ok(header);
    }
}

pub static NVALUES: u64 = 1000000;
static PCT_SET: u64 = 2; // out of 1000
static VALUE_SIZE: usize = 2;
static KEY_SIZE: usize = 20;

#[inline(always)]
fn write_key(buf: &mut Vec<u8>, key: u64) {
    let mut pushed = 0;
    let mut k = key;
    loop {
        buf.push(48 + (k % 10) as u8);
        k /= 10;
        pushed += 1;
        if k == 0 {
            break;
        }
    }
    for _ in pushed..KEY_SIZE {
        buf.push('A' as u8);
    }
}

static UDP_HEADER: &'static [u8] = &[0, 0, 0, 0, 0, 1, 0, 0];

#[derive(Copy, Clone, Debug)]
pub struct MemcachedProtocol;

impl MemcachedProtocol {
    pub fn set_request(key: u64, opaque: u32, buf: &mut Vec<u8>, tport: Transport) {
        if let Transport::Udp = tport {
            buf.extend_from_slice(UDP_HEADER);
        }

        PacketHeader {
            magic: Magic::Request as u8,
            opcode: Opcode::Set as u8,
            key_length: KEY_SIZE as u16,
            extras_length: 8,
            total_body_length: (8 + KEY_SIZE + VALUE_SIZE) as u32,
            opaque: opaque,
            ..Default::default()
        }
        .write(buf)
        .unwrap();

        buf.write_u64::<BigEndian>(0).unwrap();

        write_key(buf, key);

        for i in 0..VALUE_SIZE {
            buf.push((((key * i as u64) >> (i % 4)) & 0xff) as u8);
        }
    }

    pub fn gen_request(i: usize, p: &Packet, buf: &mut Vec<u8>, tport: Transport) {
        // Use first 32 bits of randomness to determine if this is a SET or GET req
        let low32 = p.randomness & 0xffffffff;
        let key = (p.randomness >> 32) % NVALUES;

        if low32 % 1000 < PCT_SET {
            MemcachedProtocol::set_request(key, i as u32, buf, tport);
            return;
        }

        if let Transport::Udp = tport {
            buf.extend_from_slice(UDP_HEADER);
        }

        PacketHeader {
            magic: Magic::Request as u8,
            opcode: Opcode::Get as u8,
            key_length: KEY_SIZE as u16,
            total_body_length: KEY_SIZE as u32,
            opaque: i as u32,
            ..Default::default()
        }
        .write(buf)
        .unwrap();

        write_key(buf, key);
    }

    pub fn read_response(
        mut sock: &Connection,
        tport: Transport,
        scratch: &mut [u8],
    ) -> io::Result<usize> {
        let hdr = match tport {
            Transport::Udp => {
                let len = sock.read(&mut scratch[..32])?;
                if len == 0 {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "eof"));
                }
                if len < 8 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Short packet received: {} bytes", len),
                    ));
                }
                PacketHeader::read(&mut &scratch[8..])?
            }
            Transport::Tcp => {
                sock.read_exact(&mut scratch[..24])?;
                let hdr = PacketHeader::read(&mut &scratch[..])?;
                sock.read_exact(&mut scratch[..hdr.total_body_length as usize])?;
                hdr
            }
        };

        if hdr.vbucket_id_or_status != ResponseStatus::NoError as u16 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Not NoError {}", hdr.vbucket_id_or_status),
            ));
        }
        Ok(hdr.opaque as usize)
    }
}
