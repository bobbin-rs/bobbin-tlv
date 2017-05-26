#![no_std]

extern crate cobs;
extern crate tlv;

#[derive(Debug, PartialEq)]
pub enum Error {
    CobsError(cobs::Error),
    TlvError(tlv::Error),
}

impl From<cobs::Error> for Error {
    fn from(other: cobs::Error) -> Error {
        Error::CobsError(other)
    }
}

impl From<tlv::Error> for Error {
    fn from(other: tlv::Error) -> Error {
        Error::TlvError(other)
    }
}

#[derive(Debug, PartialEq)]
pub enum Tag {
    Boot = 0x0,
    Run = 0x1,
    Exit = 0x2,
    Exception = 0x3,
    Panic = 0x4,    
    Stdin = 0x10,
    Stdout = 0x11,
    Stderr = 0x12,
    Error = 0x20,
    Warn = 0x21,
    Info = 0x22,
    Debug = 0x23,
    Trace = 0x24,
}

#[derive(Debug, PartialEq)]
pub enum Message<'a> {
    Boot(&'a [u8])
}


pub struct Reader<'a> {
    buf: &'a mut [u8],
    len: usize,
    pos: usize,
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Reader { buf: buf, len: 0, pos: 0 }
    }

    pub fn decode(&mut self, src: &[u8]) -> Result<usize, Error> {
        let mut w = cobs::Reader::new(src);
        self.len = w.read(&mut self.buf)?;
        self.pos = 0;
        Ok(self.len)
    }

    pub fn read<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Message<'b>>, Error> {
        let mut r = tlv::Reader::new(&self.buf[self.pos..]);
        if let Some((tag, value)) = r.read_tlv8(buf)? {
            match tag {
                0 => Ok(Some(Message::Boot(value))),
                _ => unimplemented!(),
            }
        } else {
            Ok(None)
        }
    }
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf: buf, pos: 0 }
    }

    pub fn boot(&mut self, msg: &[u8]) -> Result<usize, Error> {
        let mut tw = tlv::Writer::new(&mut self.buf[self.pos..]);
        let len = tw.write_tlv8(Tag::Boot as u32, msg)?;
        self.pos += len;
        Ok(len)
    }

    pub fn encode<'b>(&mut self, dst: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let len = {
            let mut w = cobs::Writer::new(dst);
            w.write(&self.buf[..self.pos])?
        };
        self.pos = 0;
        Ok(&dst[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot() {
        let mut wbuf = [0u8; 256];
        let mut w = Writer::new(&mut wbuf);

        let mut rbuf = [0u8; 256];
        let mut r = Reader::new(&mut rbuf);

        w.boot(b"Hello, World").unwrap();
        { 
            let mut out = [0u8; 256];
            let dst = w.encode(&mut out).unwrap();
            r.decode(dst).unwrap();
        }
        let mut tmp = [0u8; 256];
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Boot(b"Hello, World"))));        
    }
}
