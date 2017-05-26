#![no_std]

extern crate byteorder;
extern crate leb128;

use byteorder::{ByteOrder, BigEndian};

#[derive(Debug, PartialEq)]
pub enum Error {
    BufferTooShort,
    OutOfRange,
}

impl From<leb128::Error> for Error {
    fn from(other: leb128::Error) -> Error {
        match other {
            leb128::Error::BufferTooShort => Error::BufferTooShort,
            leb128::Error::OutOfRange => Error::OutOfRange,
        }
    }
}


pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf: buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }    

    fn as_ref(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn read_tag(&mut self) -> Result<Option<u32>, Error> {
        let (value, len) = {
            let mut r = leb128::Reader::new(self.as_ref());
            if let Some(value) = r.read_u32()? {
                (value, r.pos())
            } else {
                return Ok(None)
            }
        };
        self.pos += len;
        Ok(Some(value))
    }

    fn read_u8(&mut self) -> Result<Option<u8>, Error> {
        if self.remaining() < 1 { return Ok(None) }
        let value = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(value))
    }

    fn read_u16(&mut self) -> Result<Option<u16>, Error> {
        if self.remaining() < 2 { return Ok(None) } 
        let value = BigEndian::read_u16(self.as_ref());
        self.pos += 2;        
        Ok(Some(value))
    }

    fn read_u32(&mut self) -> Result<Option<u32>, Error> {
        if self.remaining() < 4 { return Ok(None) }
        let value = BigEndian::read_u32(self.as_ref());
        self.pos += 4;
        Ok(Some(value))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        let len = buf.len();
        if len > self.remaining() { return Ok(None) }
        buf.copy_from_slice(&self.buf[self.pos..(self.pos + len)]);
        self.pos += len;
        Ok(Some(len))
    }

    pub fn read_tlv8<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<(u32, &'b [u8])>, Error> {
        if let Some(tag) = self.read_tag()? {
            if let Some(len) = self.read_u8()? {
                let len = len as usize;
                if let Some(n) = self.read(&mut buf[..len])? {
                    return Ok(Some((tag, &buf[..n])))
                } else {
                    return Ok(None)
                }
            } else {
                return Ok(None)
            }
        } else {
            return Ok(None)
        }        
    }

    pub fn read_tlv16<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<(u32, &'b [u8])>, Error> {
        if let Some(tag) = self.read_tag()? {
            if let Some(len) = self.read_u16()? {
                let len = len as usize;
                if let Some(n) = self.read(&mut buf[..len])? {
                    return Ok(Some((tag, &buf[..n])))
                } else {
                    return Ok(None)
                }
            } else {
                return Ok(None)
            }
        } else {
            return Ok(None)
        }        
    }    

    pub fn read_tlv32<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<(u32, &'b [u8])>, Error> {
        if let Some(tag) = self.read_tag()? {
            if let Some(len) = self.read_u32()? {
                let len = len as usize;
                if let Some(n) = self.read(&mut buf[..len])? {
                    return Ok(Some((tag, &buf[..n])))
                } else {
                    return Ok(None)
                }
            } else {
                return Ok(None)
            }
        } else {
            return Ok(None)
        }        
    }    

}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf: buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn cap(&self) -> usize {
        self.buf.len()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.pos..]
    }

    fn write_tag(&mut self, tag: u32) -> Result<usize, Error> {
        let len = {
            let mut w = leb128::Writer::new(self.as_mut());
            w.write_u32(tag)?;
            w.pos()
        };
        self.pos += len;
        Ok(len)
    }

    fn write_u8(&mut self, value: u8) -> Result<usize, Error> {
        if self.remaining() < 1 { return Err(Error::BufferTooShort) }
        self.buf[self.pos] = value;
        self.pos += 1;
        Ok(1)
    }

    fn write_u16(&mut self, value: u16) -> Result<usize, Error> {
        if self.remaining() < 2 { return Err(Error::BufferTooShort) }
        BigEndian::write_u16(&mut self.buf[self.pos..], value);
        self.pos += 2;
        Ok(2)
    }

    fn write_u32(&mut self, value: u32) -> Result<usize, Error> {
        if self.remaining() < 2 { return Err(Error::BufferTooShort) }
        BigEndian::write_u32(&mut self.buf[self.pos..], value);
        self.pos += 4;
        Ok(4)
    }

    fn write(&mut self, value: &[u8]) -> Result<usize, Error> {
        let len = value.len();
        if self.remaining() < len { return Err(Error::BufferTooShort) }
        &mut self.buf[self.pos..(self.pos + len)].copy_from_slice(value);
        self.pos += len;
        Ok(len)
    }

    pub fn write_tlv8(&mut self, tag: u32, value: &[u8]) -> Result<usize, Error> {
        let len = value.len();
        if len >> 8 != 0 { return Err(Error::OutOfRange) }        
        Ok(self.write_tag(tag)? + self.write_u8(len as u8)? + self.write(value)?)
    }

    pub fn write_tlv16(&mut self, tag: u32, value: &[u8]) -> Result<usize, Error> {
        let len = value.len();
        if len >> 16 != 0 { return Err(Error::OutOfRange) }        
        Ok(self.write_tag(tag)? + self.write_u16(len as u16)? + self.write(value)?)
    }

    pub fn write_tlv32(&mut self, tag: u32, value: &[u8]) -> Result<usize, Error> {
        let len = value.len();
        if len >> 32 != 0 { return Err(Error::OutOfRange) }
        Ok(self.write_tag(tag)? + self.write_u32(len as u32)? + self.write(value)?)
    }

    pub fn write_atlv8(&mut self, addr: &[u8], tag: u32, value: &[u8]) -> Result<usize, Error> {
        let alen = addr.len();
        if alen >> 8 != 0 { return Err(Error::OutOfRange) }        
        let len = value.len();
        if len >> 8 != 0 { return Err(Error::OutOfRange) }        
        Ok(self.write_u8(alen as u8)? + self.write(addr)? + self.write_tag(tag)? + self.write_u8(len as u8)? + self.write(value)?)
    }

    pub fn write_alv16(&mut self, addr: &[u8], tag: u32, value: &[u8]) -> Result<usize, Error> {
        let alen = addr.len();
        if alen >> 16 != 0 { return Err(Error::OutOfRange) }        
        let len = value.len();
        if len >> 16 != 0 { return Err(Error::OutOfRange) }        
        Ok(self.write_u16(alen as u16)? + self.write(addr)? + self.write_tag(tag)? + self.write_u16(len as u16)? + self.write(value)?)
    }

    pub fn write_alv32(&mut self, addr: &[u8], tag: u32, value: &[u8]) -> Result<usize, Error> {
        let alen = addr.len();
        let len = value.len();
        if len >> 32 != 0 { return Err(Error::OutOfRange) }
        Ok(self.write_u32(alen as u32)? + self.write(addr)? + self.write_tag(tag)? + self.write_u32(len as u32)? + self.write(value)?)
    }    
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv8() {
        let value = b"Hello, World";
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_tlv8(0x1234, value).unwrap();
        assert_eq!(w.pos(), 2 + 1 + value.len());
        let mut r = Reader::new(w.as_ref());
        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv8(&mut out).unwrap().unwrap();
        assert_eq!(tag, 0x1234);
        assert_eq!(msg, value);
    }

    #[test]
    fn test_tlv16() {
        let value = b"Hello, World";
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_tlv16(0x1234, value).unwrap();   
        assert_eq!(w.pos(), 2 + 2 + value.len());
        let mut r = Reader::new(w.as_ref());
        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv16(&mut out).unwrap().unwrap();
        assert_eq!(tag, 0x1234);
        assert_eq!(msg, &value[..]);
    }

    #[test]
    fn test_tlv32() {
        let value = b"Hello, World";
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_tlv32(0x1234, value).unwrap();
        assert_eq!(w.pos(), 2 + 4 + value.len());
        let mut r = Reader::new(w.as_ref());
        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv32(&mut out).unwrap().unwrap();
        assert_eq!(tag, 0x1234);
        assert_eq!(msg, &value[..]);
    }    

    #[test]
    fn test_tlv8_seq() {
        let (t1, v1) = (0x01, b"Hello, World");
        let (t2, v2) = (0x02, b"Hi, There");
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_tlv8(t1, v1).unwrap();
        assert_eq!(w.pos(), 1 + 1 + v1.len());
        w.write_tlv8(t2, v2).unwrap();
        assert_eq!(w.pos(), 1 + 1 + v1.len() + 1 + 1 + v2.len());

        let mut r = Reader::new(w.as_ref());
        let mut out = [0u8; 256];

        let (tag, msg) = r.read_tlv8(&mut out).unwrap().unwrap();
        assert_eq!(tag, t1);        
        assert_eq!(msg, &v1[..]);

        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv8(&mut out).unwrap().unwrap();
        assert_eq!(tag, t2);
        assert_eq!(msg, &v2[..]);
    }

    #[test]
    fn test_tlv16_seq() {
        let (t1, v1) = (0x01, b"Hello, World");
        let (t2, v2) = (0x02, b"Hi, There");
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_tlv16(t1, v1).unwrap();
        assert_eq!(w.pos(), 1 + 2 + v1.len());
        w.write_tlv16(t2, v2).unwrap();
        assert_eq!(w.pos(), 1 + 2 + v1.len() + 1 + 2 + v2.len());

        let mut r = Reader::new(w.as_ref());

        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv16(&mut out).unwrap().unwrap();
        assert_eq!(tag, t1);        
        assert_eq!(msg, &v1[..]);

        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv16(&mut out).unwrap().unwrap();
        assert_eq!(tag, t2);
        assert_eq!(msg, &v2[..]);
    }

    #[test]
    fn test_tlv32_seq() {
        let (t1, v1) = (0x01, b"Hello, World");
        let (t2, v2) = (0x02, b"Hi, There");
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_tlv32(t1, v1).unwrap();
        assert_eq!(w.pos(), 1 + 4 + v1.len());
        w.write_tlv32(t2, v2).unwrap();
        assert_eq!(w.pos(), 1 + 4 + v1.len() + 1 + 4 + v2.len());

        let mut r = Reader::new(w.as_ref());

        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv32(&mut out).unwrap().unwrap();
        assert_eq!(tag, t1);        
        assert_eq!(msg, &v1[..]);

        let mut out = [0u8; 256];
        let (tag, msg) = r.read_tlv32(&mut out).unwrap().unwrap();
        assert_eq!(tag, t2);
        assert_eq!(msg, &v2[..]);
    }
        
    
}
