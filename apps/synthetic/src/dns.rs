
use byteorder::{BigEndian, WriteBytesExt};

use Packet;

use dns_parser::{QueryClass, QueryType, Header, Opcode, ResponseCode, Name};

use std::io::Write;
use std::str::from_utf8;

const NDOMAINS : u64 = 100000;

pub fn create_request(i: usize, packet: &Packet, buf: &mut Vec<u8>) {

	let h = Header {
		id: i as u16,
		query: true,
		opcode: Opcode::StandardQuery,
		authoritative: false,
		truncated: false,
		recursion_desired: false,
		recursion_available: false,
		authenticated_data: false,
		checking_disabled: false,
		response_code: ResponseCode::NoError,
		questions: 1,
		answers: 0,
		nameservers: 0,
		additional: 0,
	};

	for _ in 0..12 {
		buf.push(0);
	}
	h.write(&mut buf[..12]);

	buf.push(0);
	let len1 = buf.len();
	buf.write_fmt(format_args!("{}", i)).unwrap();
	buf[len1-1] = (buf.len() - len1) as u8;

	buf.push(0);
	let len2 = buf.len();
	buf.write_fmt(format_args!("{}", packet.randomness % NDOMAINS)).unwrap();
	buf[len2-1] = (buf.len() - len2) as u8;

	buf.push(3);
	buf.extend("com".as_bytes());

	buf.push(0);
	buf.write_u16::<BigEndian>(QueryType::A as u16).unwrap();
	buf.write_u16::<BigEndian>(QueryClass::IN as u16 | 0x8000).unwrap();

}

pub fn parse_response(buf: &[u8]) -> Result<usize, ()> {

	if Header::parse(buf).is_err() || buf[Header::size()] & 0b1100_0000 != 0 {
		return Err(());
	}

	let pos = Header::size();
	let end = pos + buf[pos] as usize + 1;

	let i = usize::from_str_radix(from_utf8(&buf[pos+1..end]).unwrap(), 10).unwrap();

	return Ok(i);
}
