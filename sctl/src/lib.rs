#![no_std]

extern crate cobs;
extern crate tlv;

use core::convert::AsRef;

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
    Boot = 0x1,
    Run = 0x2,
    Exit = 0x3,
    Exception = 0x4,
    Panic = 0x5,
    Stdin = 0x10,
    Stdout = 0x11,
    Stderr = 0x12,
    Error = 0x20,
    Warn = 0x21,
    Info = 0x22,
    Debug = 0x23,
    Trace = 0x24,
    Val = 0x30,
    Get = 0x31,
    Set = 0x32,
}

#[derive(Debug, PartialEq)]
pub enum Message<'a> {
    Boot(&'a [u8]),
    Run(&'a [u8]),
    Exit(u8),
    Exception(&'a [u8]),
    Panic(&'a [u8]),
    Stdin(&'a [u8]),
    Stdout(&'a [u8]),
    Stderr(&'a [u8]),
    Error(&'a [u8]),
    Warn(&'a [u8]),
    Info(&'a [u8]),
    Debug(&'a [u8]),
    Trace(&'a [u8]),
    Val(&'a [u8]),    
    Get(&'a [u8]),
    Set(&'a [u8]),
}

pub struct Reader<'a> {
    buf: &'a [u8],
    len: usize,
    pos: usize,
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf: buf, len: 0, pos: 0 }
    }

    // pub fn decode(&mut self, src: &[u8]) -> Result<usize, Error> {
    //     let mut w = cobs::Reader::new(src);
    //     self.len = w.read(&mut self.buf)?;
    //     self.pos = 0;
    //     Ok(self.len)
    // }

    pub fn read<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Message<'b>>, Error> {
        let mut r = tlv::Reader::new(&self.buf[self.pos..]);
        if let Some((tag, value)) = r.read_tlv8(buf)? {
            self.pos += r.pos();
            match tag {
                0x1 => Ok(Some(Message::Boot(value))),
                0x2 => Ok(Some(Message::Run(value))),
                0x3 => Ok(Some(Message::Exit(value[0]))),
                0x4 => Ok(Some(Message::Exception(value))),
                0x5 => Ok(Some(Message::Panic(value))),
                0x10 => Ok(Some(Message::Stdin(value))),
                0x11 => Ok(Some(Message::Stdout(value))),
                0x12 => Ok(Some(Message::Stderr(value))),
                0x20 => Ok(Some(Message::Error(value))),
                0x21 => Ok(Some(Message::Warn(value))),
                0x22 => Ok(Some(Message::Info(value))),
                0x23 => Ok(Some(Message::Debug(value))),
                0x24 => Ok(Some(Message::Trace(value))),
                0x30 => Ok(Some(Message::Val(value))),
                0x31 => Ok(Some(Message::Get(value))),
                0x32 => Ok(Some(Message::Set(value))),
                _ => unimplemented!(),
            }
        } else {
            Ok(None)
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn remaining(&self) -> usize {
        self.len - self.pos
    }
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf: buf, pos: 0 }
    }

    pub fn encode<'b>(&mut self, dst: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let len = {
            let mut w = cobs::Writer::new(dst);
            w.encode_packet(&self.buf[..self.pos])?
        };
        self.pos = 0;
        Ok(&dst[..len])
    }

    fn write_tlv(&mut self, tag: Tag, value: &[u8]) -> Result<usize, Error> {
        let mut tw = tlv::Writer::new(&mut self.buf[self.pos..]);
        let len = tw.write_tlv8(tag as u32, value)?;
        self.pos += len;
        Ok(len)
    }

    pub fn boot(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Boot, value)
    }

    pub fn run(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Run, value)
    }    

    pub fn exception(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Exception, value)
    }    

    pub fn panic(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Panic, value)
    }    

    pub fn exit(&mut self, value: u8) -> Result<usize, Error> {        
        self.write_tlv(Tag::Exit, &[value])
    }    

    pub fn stdin(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Stdin, value)
    }    

    pub fn stdout(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Stdout, value)
    }    

    pub fn stderr(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Stderr, value)
    }

    pub fn error(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Error, value)
    }  

    pub fn warn(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Warn, value)
    }  

    pub fn info(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Info, value)
    }  

    pub fn debug(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Debug, value)
    }  

    pub fn trace(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Trace, value)
    }  

    pub fn val(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Val, value)
    }  

    pub fn get(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Get, value)
    }  

    pub fn set(&mut self, value: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Set, value)
    }  

}

impl<'a> AsRef<[u8]> for Writer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot() {
        let mut wbuf = [0u8; 1024];
        let mut w = Writer::new(&mut wbuf);

        w.boot(b"Hello, World").unwrap();
        w.run(b"Testing").unwrap();
        w.exception(b"Exception").unwrap();
        w.panic(b"Panic").unwrap();
        w.stdin(b"stdin").unwrap();
        w.stdout(b"stdout").unwrap();
        w.stderr(b"stderr").unwrap();
        w.warn(b"warn").unwrap();
        w.info(b"info").unwrap();
        w.debug(b"debug").unwrap();
        w.trace(b"trace").unwrap();
        w.val(b"val").unwrap();
        w.get(b"get").unwrap();
        w.set(b"set").unwrap();
        w.exit(0x55).unwrap();

        let mut r = Reader::new(w.as_ref());
        let mut tmp = [0u8; 256];
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Boot(b"Hello, World"))));        
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Run(b"Testing"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Exception(b"Exception"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Panic(b"Panic"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Stdin(b"stdin"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Stdout(b"stdout"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Stderr(b"stderr"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Warn(b"warn"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Info(b"info"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Debug(b"debug"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Trace(b"trace"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Val(b"val"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Get(b"get"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Set(b"set"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Exit(0x55))));
    }
}
