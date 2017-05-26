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
            self.pos += r.pos();
            match tag {
                0x0 => Ok(Some(Message::Boot(value))),
                0x1 => Ok(Some(Message::Run(value))),
                0x2 => Ok(Some(Message::Exit(value[0]))),
                0x3 => Ok(Some(Message::Exception(value))),
                0x4 => Ok(Some(Message::Panic(value))),
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
                0x32 => Ok(Some(Message::Get(value))),
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

    pub fn encode<'b>(&mut self, dst: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let len = {
            let mut w = cobs::Writer::new(dst);
            w.write(&self.buf[..self.pos])?
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

    pub fn val(&mut self, tmp: &mut [u8], key: &[u8], value: &[u8]) -> Result<usize, Error> {
        let mut w = tlv::Writer::new(tmp);
        w.write_lv8(key)?;
        w.write_lv8(value)?;
        self.write_tlv(Tag::Val, w.as_ref())
    }  

    pub fn get(&mut self, key: &[u8]) -> Result<usize, Error> {
        self.write_tlv(Tag::Get, key)
    }  

    pub fn set(&mut self, tmp: &mut[u8], key: &[u8], value: &[u8]) -> Result<usize, Error> {
        let mut w = tlv::Writer::new(tmp);
        w.write_lv8(key)?;
        w.write_lv8(value)?;
        self.write_tlv(Tag::Set, w.as_ref())
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
        w.run(b"Testing").unwrap();
        w.stdout(b"abcdef").unwrap();
        w.exit(0x55).unwrap();;
        { 
            let mut out = [0u8; 256];
            let dst = w.encode(&mut out).unwrap();
            r.decode(dst).unwrap();
        }
        let mut tmp = [0u8; 256];
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Boot(b"Hello, World"))));        
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Run(b"Testing"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Stdout(b"abcdef"))));
        assert_eq!(r.read(&mut tmp[..]), Ok(Some(Message::Exit(0x55))));
    }
}
