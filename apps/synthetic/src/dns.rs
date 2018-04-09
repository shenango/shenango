
use byteorder::{BigEndian, WriteBytesExt};

use Packet;

use dns_parser::{QueryClass, QueryType, Header, Opcode, ResponseCode, Name};

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
	buf.extend([0u8; 12].iter());
	h.write(&mut buf[..12]);

	let subd = i.to_string();
	buf.push(subd.len() as u8);
	buf.extend(subd.as_bytes());

	let subd = (packet.randomness % NDOMAINS).to_string();
	buf.push(subd.len() as u8);
	buf.extend(subd.as_bytes());

	buf.push("com".len() as u8);
	buf.extend("com".as_bytes());

	buf.push(0);
	buf.write_u16::<BigEndian>(QueryType::A as u16).unwrap();
	buf.write_u16::<BigEndian>(QueryClass::IN as u16 | 0x8000).unwrap();

}

pub fn parse_response(buf: &[u8]) -> Result<usize, ()> {

	if Header::parse(buf).is_err() {
		return Err(());
	}

	let name = Name::scan(&buf[Header::size()..], buf).unwrap().to_string();

	let t : &str = name.split(".").nth(0).unwrap();

	let i = usize::from_str_radix(t, 10).unwrap();

	return Ok(i);
}
