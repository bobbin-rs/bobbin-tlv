#![no_std]

//! Consistent Overhead Byte Stuffing
//! Original Paper: http://www.stuartcheshire.org/papers/COBSforToN.pdf
//! IETF Draft: https://tools.ietf.org/html/draft-ietf-pppext-cobs-00
//! Wikipedia: https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing
//! See https://bitbucket.org/cmcqueen1975/cobs-c/wiki/Home

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidEncoding,
    BufferTooShort,
    MissingTerminator,
}

/// Encodes a slice into dst, returning the number of dst bytes used. dst must be at least one byte longer than src.
pub fn encode(src: &[u8], dst: &mut[u8]) -> Result<usize, Error> {
    let mut p = 0;
    let mut d = 1;
    let mut cp = 0;
    let mut code = 0x01;
    let slen = src.len();
    let dlen = dst.len();    
    while p < slen {
        if src[p] == 0 {
            if cp >= dlen {
                return Err(Error::BufferTooShort)
            }
            dst[cp] = code;
            cp = d;
            d += 1;
            code = 0x01;
        } else {
            if d >= dlen {
                return Err(Error::BufferTooShort)
            }
            dst[d] = src[p];
            d += 1;
            code += 1;
            if code == 0xff {
                if cp >= dlen {
                    return Err(Error::BufferTooShort)
                }
                dst[cp] = code;
                cp = d;
                d += 1;
                code = 0x01;
            }
        }
        p += 1;
    }
    if cp >= dlen {
        return Err(Error::BufferTooShort)
    }    
    dst[cp] = code;
    Ok(d)
}

/// Decodes a message from src into dst, returning the number of dst bytes used. The length of dst must be at least than src.len() - 1.
pub fn decode(src: &[u8], dst: &mut[u8]) -> Result<usize, Error> {
    let mut p = 0;
    let mut d = 0;
    let slen = src.len();
    let dlen = dst.len();
    loop {
        let code = src[p];        
        p += 1;
        let mut i = 1;
        while i < code {
            if d >= dlen {
                return Err(Error::BufferTooShort)
            }
            dst[d] = src[p];
            d += 1;
            p += 1;            
            i += 1;
        }
        if p >= slen {
            return Ok(d)
        }
        if code < 0xff {
            if d >= dlen {
                return Err(Error::BufferTooShort)
            }
            dst[d] = 0;
            d += 1;
        }
    }    
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
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
        self.cap() - self.pos()
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    // Returns the number of bytes used by the encoder, including the null termintor.
    pub fn write(&mut self, src: &[u8]) -> Result<usize, Error> {
        let n = encode(src, &mut self.buf[self.pos..])?;
        if self.pos + n + 1 > self.buf.len() {
            return Err(Error::BufferTooShort)
        }
        self.buf[self.pos + n] = 0x00;
        self.pos += n + 1;
        Ok(n + 1)
    }
}

pub struct Reader<'a> {
    buf: &'a mut [u8],
    head: usize,
    tail: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Reader { buf: buf, head: 0, tail: 0 }
    }

    pub fn pos(&self) -> usize {
        self.head
    }

    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.tail
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.tail..]
    }

    pub fn extend(&mut self, len: usize) {
        self.tail += len;
    }
    
    // Returns the number of bytes used in dst
    pub fn read(&mut self, dst: &mut [u8]) -> Result<Option<usize>, Error> {
        // find terminator
        let mut t = self.head;
        while t < self.tail {
            if self.buf[t] == 0 {
                break
            }
            t += 1;
        }
        if t == self.tail {
            return Ok(None)
        }
        let n = decode(&self.buf[self.head..t], dst)?;
        self.head = t + 1;
        Ok(Some(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U1: [u8; 1] = [0x00];
    const E1: [u8; 2] = [0x01, 0x01];
    
    const U2: [u8; 2] = [0x00, 0x00];
    const E2: [u8; 3] = [0x01, 0x01, 0x01];

    const U3: [u8; 4] = [0x11, 0x22, 0x00, 0x33];
    const E3: [u8; 5] = [0x03, 0x11, 0x22, 0x02, 0x33];

    const U4: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    const E4: [u8; 5] = [0x05, 0x11, 0x22, 0x33, 0x44];

    const U5: [u8; 4] = [0x11, 0x00, 0x00, 0x00];
    const E5: [u8; 5] = [0x02, 0x11, 0x01, 0x01, 0x01];

    #[test]
    fn test_predefined() {
        let predefined_encodings = [
            ( &b""[..],                                  &b"\x01"[..]                                               ),
            ( &b"1"[..],                                 &b"\x021"[..]                                              ),
            ( &b"12345"[..],                             &b"\x0612345"[..]                                          ),
            ( &b"12345\x006789"[..],                     &b"\x0612345\x056789"[..]                                  ),
            ( &b"\x0012345\x006789"[..],                 &b"\x01\x0612345\x056789"[..]                              ),
            ( &b"12345\x006789\x00"[..],                 &b"\x0612345\x056789\x01"[..]                              ),
            ( &b"\x00"[..],                              &b"\x01\x01"[..]                                           ),
            ( &b"\x00\x00"[..],                          &b"\x01\x01\x01"[..]                                       ),
            ( &b"\x00\x00\x00"[..],                      &b"\x01\x01\x01\x01"[..]                                   ),
        ];

        for &(u, e) in predefined_encodings.iter() {
            let mut buf = [0xffu8; 64];
            let dst = &mut buf[..e.len()];
            assert_eq!(encode(&u, dst).unwrap(), e.len());
            assert_eq!(e, dst);            
        }

        for &(u, e) in predefined_encodings.iter() {
            let mut buf = [0xffu8; 64];
            let dst = &mut buf[..u.len()];
            assert_eq!(decode(&e, dst).unwrap(), u.len());
            assert_eq!(u, dst);            
        }
    }

    #[test]
    fn test_encode() {
        let mut dst = [0xffu8; 256];
        assert_eq!(encode(&U1[..], &mut dst[..1]), Err(Error::BufferTooShort));
        assert_eq!(encode(&U1[..], &mut dst[..2]), Ok(2));
        assert_eq!(encode(&U1[..], &mut dst[..3]), Ok(2));
        assert_eq!(E1, &dst[..2]);

        let mut dst = [0xffu8; 256];
        assert_eq!(encode(&U2[..], &mut dst[..2]), Err(Error::BufferTooShort));
        assert_eq!(encode(&U2[..], &mut dst[..3]), Ok(3));
        assert_eq!(encode(&U2[..], &mut dst[..4]), Ok(3));
        assert_eq!(E2, &dst[..3]);

        let mut dst = [0xffu8; 256];
        assert_eq!(encode(&U3[..], &mut dst[..4]), Err(Error::BufferTooShort));
        assert_eq!(encode(&U3[..], &mut dst[..5]), Ok(5));
        assert_eq!(encode(&U3[..], &mut dst[..6]), Ok(5));
        assert_eq!(E3, &dst[..5]);

        let mut dst = [0xffu8; 256];
        assert_eq!(encode(&U4[..], &mut dst[..4]), Err(Error::BufferTooShort));
        assert_eq!(encode(&U4[..], &mut dst[..5]), Ok(5));
        assert_eq!(encode(&U4[..], &mut dst[..6]), Ok(5));
        assert_eq!(E4, &dst[..5]);

        let mut dst = [0xffu8; 256];
        assert_eq!(encode(&U5[..], &mut dst[..4]), Err(Error::BufferTooShort));
        assert_eq!(encode(&U5[..], &mut dst[..5]), Ok(5));
        assert_eq!(encode(&U5[..], &mut dst[..6]), Ok(5));
        assert_eq!(E5, &dst[..5]);
    }

    #[test]
    fn test_decode() {
        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E1[..], &mut dst[..0]), Err(Error::BufferTooShort));
        assert_eq!(decode(&E1[..], &mut dst[..1]), Ok(1));
        assert_eq!(decode(&E1[..], &mut dst[..2]), Ok(1));
        assert_eq!(U1, &dst[..1]);

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E2[..], &mut dst[..1]), Err(Error::BufferTooShort));
        assert_eq!(decode(&E2[..], &mut dst[..2]), Ok(2));
        assert_eq!(decode(&E2[..], &mut dst[..3]), Ok(2));
        assert_eq!(U2, &dst[..2]);

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E3[..], &mut dst[..3]), Err(Error::BufferTooShort));
        assert_eq!(decode(&E3[..], &mut dst[..4]), Ok(4));
        assert_eq!(decode(&E3[..], &mut dst[..5]), Ok(4));
        assert_eq!(U3, &dst[..4]);        

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E4[..], &mut dst[..3]), Err(Error::BufferTooShort));
        assert_eq!(decode(&E4[..], &mut dst[..4]), Ok(4));
        assert_eq!(decode(&E4[..], &mut dst[..5]), Ok(4));
        assert_eq!(U4, &dst[..4]);    

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E5[..], &mut dst[..3]), Err(Error::BufferTooShort));
        assert_eq!(decode(&E5[..], &mut dst[..4]), Ok(4));
        assert_eq!(decode(&E5[..], &mut dst[..5]), Ok(4));
        assert_eq!(U5, &dst[..4]);            
    }

    #[test]
    fn test_encoder_len() {
        let mut enc_buf = [0u8; 0];        
        let mut encoder = Writer::new(&mut enc_buf);        
        assert_eq!(encoder.write(&U1[..]), Err(Error::BufferTooShort));

        let mut enc_buf = [0u8; 1];
        let mut encoder = Writer::new(&mut enc_buf);        
        assert_eq!(encoder.write(&U1[..]), Err(Error::BufferTooShort));

        let mut enc_buf = [0u8; 2];
        let mut encoder = Writer::new(&mut enc_buf);        
        assert_eq!(encoder.write(&U1[..]), Err(Error::BufferTooShort));

        let mut enc_buf = [0u8; 3];
        let mut encoder = Writer::new(&mut enc_buf);        
        assert_eq!(encoder.write(&U1[..]), Ok(3));
        assert_eq!(encoder.remaining(), 0);
    }

    #[test]
    fn test_encoder_decoder() {
        let mut enc_buf = [0xffu8; 256];        
        let mut encoder = Writer::new(&mut enc_buf);

        assert_eq!(encoder.write(&U1[..]), Ok(3));
        assert_eq!(&encoder.as_ref()[..2], &E1[..]);
        assert_eq!(encoder.as_ref()[2], 0);

        assert_eq!(encoder.write(&U2[..]), Ok(4));
        assert_eq!(&encoder.as_ref()[3..6], &E2[..]);
        assert_eq!(encoder.as_ref()[6], 0);

        assert_eq!(encoder.write(&U3[..]), Ok(6));
        assert_eq!(&encoder.as_ref()[7..12], &E3[..]);
        assert_eq!(encoder.as_ref()[12], 0);

        assert_eq!(encoder.write(&U4[..]), Ok(6));
        assert_eq!(&encoder.as_ref()[13..18], &E4[..]);
        assert_eq!(encoder.as_ref()[18], 0);        

        assert_eq!(encoder.write(&U5[..]), Ok(6));
        assert_eq!(&encoder.as_ref()[19..24], &E5[..]);
        assert_eq!(encoder.as_ref()[24], 0);      

        assert_eq!(encoder.write(b""), Ok(2));
        assert_eq!(encoder.as_ref()[25], 1);
        assert_eq!(encoder.as_ref()[26], 0);
        assert_eq!(encoder.pos(), 27);

        let mut dec_buf = [0u8; 1024];
        let mut decoder = Reader::new(&mut dec_buf);
        &mut decoder.as_mut()[..encoder.pos()].copy_from_slice(&encoder.as_ref());
        decoder.extend(encoder.pos());

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..1]), Ok(Some(1)));
        assert_eq!(&dst[..1], &U1[..]);
        assert_eq!(decoder.pos(), 3);

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..2]), Ok((Some(2))));
        assert_eq!(&dst[..2], &U2[..]);
        assert_eq!(decoder.pos(), 7);

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..4]), Ok(Some(4)));
        assert_eq!(&dst[..4], &U3[..]);
        assert_eq!(decoder.pos(), 13);

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..4]), Ok(Some(4)));
        assert_eq!(&dst[..4], &U4[..]);
        assert_eq!(decoder.pos(), 19);        

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..4]), Ok(Some(4)));
        assert_eq!(&dst[..4], &U5[..]);
        assert_eq!(decoder.pos(), 25);          

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..0]), Ok(Some(0)));
        assert_eq!(decoder.pos(), 27);
        assert_eq!(decoder.len(), 0);

        let mut dst = [0xffu8; 255];        
        assert_eq!(decoder.read(&mut dst[..0]), Ok(None));
        assert_eq!(decoder.pos(), 27);
        assert_eq!(decoder.len(), 0);        
    }
}
