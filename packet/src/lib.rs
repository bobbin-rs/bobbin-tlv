#![no_std]

#[derive(Debug, PartialEq)]
pub enum Error {
    Overflow,
    Underflow,
    UnknownTag,
}

#[derive(Debug, PartialEq)]
pub enum Message<'a> {
    Boot(&'a [u8]), // 0x01
    Run(&'a [u8]), // 0x02
    Exit(&'a [u8]), // 0x03
    Exception(&'a [u8]), // 0x04
    Panic(&'a [u8]), // 0x05
    Stdin(&'a [u8]), // 0x10
    Stdout(&'a [u8]), // 0x11
    Stderr(&'a [u8]), // 0x12
    Other(u8, &'a [u8]),
}

impl<'a> From<(u8, &'a[u8])> for Message<'a> {
    fn from(other: (u8, &'a [u8])) -> Message<'a> {
        use Message::*;
        match other.0 {
            0x01 => Boot(other.1),
            0x02 => Run(other.1),
            0x03 => Exit(other.1),
            0x04 => Exception(other.1),
            0x05 => Panic(other.1),
            0x10 => Stdin(other.1),
            0x11 => Stdout(other.1),
            0x12 => Stderr(other.1),
            _ => Other(other.0, other.1),
        }
    }
}

impl<'a> Into<(u8, &'a [u8])> for Message<'a> {
    fn into(self) -> (u8, &'a [u8]) {
        use Message::*;
        match self {
            Boot(ref value) => (0x01, value),            
            Run(ref value) => (0x02, value),
            Exit(ref value) => (0x03, value),
            Exception(ref value) => (0x04, value),
            Panic(ref value) => (0x05, value),
            Stdin(ref value) => (0x10, value),
            Stdout(ref value) => (0x11, value),
            Stderr(ref value) => (0x12, value),
            Other(tag, ref value) => (tag, value),
        }
    }
}

pub fn encode_message<'a>(dst: &'a mut [u8], msg: Message) -> Result<&'a[u8], Error> {
    encode(dst, msg.into())
}

pub fn encode<'a>(dst: &'a mut [u8], msg: (u8, &[u8])) -> Result<&'a[u8], Error> {
    let (tag, value) = msg;
    let len = value.len();
    if len > 255 || len + 2 > dst.len() {
        return Err(Error::Overflow)
    }    
    dst[0] = tag;
    dst[1] = len as u8;
    dst[2..len + 2].copy_from_slice(value);
    Ok(&dst[..len + 2])
}

pub fn decode_message<'a>(src: &'a [u8]) -> Result<Message, Error> {
    decode(src).map(Message::from)
}

pub fn decode<'a>(src: &'a [u8]) -> Result<(u8, &'a [u8]), Error> {
    if src.len() < 2 {
        return Err(Error::Underflow)
    }
    let tag = src[0];
    let len = src[1] as usize;
    if src.len() < len + 2 {
        return Err(Error::Underflow)
    }
    Ok((tag, &src[2..2 + len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const U0: (u8, &[u8]) = (0x01, &[0x01, 0x02, 0x03, 0x04]);
    const E0: [u8; 6] = [0x01, 0x04, 0x01, 0x02, 0x03, 0x04];

    const U1: (u8, &[u8]) = (0x02, &[]);
    const E1: [u8; 2] = [0x02, 0x00];


    #[test]
    fn test_encode() {
        let mut tmp = [0u8; 64];
        assert_eq!(encode(&mut tmp, U0).unwrap(), &E0);
        assert_eq!(encode(&mut tmp, U1).unwrap(), &E1);
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode(&E0).unwrap(), U0);
        assert_eq!(decode(&E1).unwrap(), U1);
    }

    #[test]
    fn test_encode_message() {
        let mut tmp = [0u8; 64];
        assert_eq!(encode_message(&mut tmp, Message::Boot(U0.1)).unwrap(), &E0);
        assert_eq!(encode_message(&mut tmp, Message::Run(U1.1)).unwrap(), &E1);
    }
    #[test]
    fn test_decode_message() {
        assert_eq!(decode_message(&E0).unwrap(), Message::Boot(U0.1));
        assert_eq!(decode_message(&E1).unwrap(), Message::Run(U1.1));

    }
}