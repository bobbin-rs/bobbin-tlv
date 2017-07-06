//#![no_std]

//! Consistent Overhead Byte Stuffing
//! Original Paper: http://www.stuartcheshire.org/papers/COBSforToN.pdf
//! IETF Draft: https://tools.ietf.org/html/draft-ietf-pppext-cobs-00
//! Wikipedia: https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing
//! See https://bitbucket.org/cmcqueen1975/cobs-c/wiki/Home

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidEncoding,
    BufferTooShort,
    SourceTooShort,
    DestTooShort,
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
    println!("decode: {:?} {:?}", src, dst);    
    let (mut s, mut d) = (0, 0);
    let len = src.len();
    let mut code;
    let mut i;

    if dst.len() + 1 < src.len() {
        return Err(Error::DestTooShort)
    }

    while s < len {    
        code = src[s] as usize;        
        if s + code > len && code != 1 {
            return Err(Error::SourceTooShort)
        }
        s += 1;
        i = 1;
        while i < code {
            dst[d] = src[s];
            d += 1;
            s += 1;
            i += 1;
        }
        if code != 0xFF && s != len {        
            dst[d] = 0;
            d += 1;
        }
    }
    return Ok(d)
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
        assert_eq!(decode(&E1[..], &mut dst[..0]), Err(Error::DestTooShort));
        assert_eq!(decode(&E1[..], &mut dst[..1]), Ok(1));
        assert_eq!(decode(&E1[..], &mut dst[..2]), Ok(1));
        assert_eq!(U1, &dst[..1]);

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E2[..], &mut dst[..1]), Err(Error::DestTooShort));
        assert_eq!(decode(&E2[..], &mut dst[..2]), Ok(2));
        assert_eq!(decode(&E2[..], &mut dst[..3]), Ok(2));
        assert_eq!(U2, &dst[..2]);

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E3[..], &mut dst[..3]), Err(Error::DestTooShort));
        assert_eq!(decode(&E3[..], &mut dst[..4]), Ok(4));
        assert_eq!(decode(&E3[..], &mut dst[..5]), Ok(4));
        assert_eq!(U3, &dst[..4]);        

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E4[..], &mut dst[..3]), Err(Error::DestTooShort));
        assert_eq!(decode(&E4[..], &mut dst[..4]), Ok(4));
        assert_eq!(decode(&E4[..], &mut dst[..5]), Ok(4));
        assert_eq!(U4, &dst[..4]);    

        let mut dst = [0xffu8; 255];
        assert_eq!(decode(&E5[..], &mut dst[..3]), Err(Error::DestTooShort));
        assert_eq!(decode(&E5[..], &mut dst[..4]), Ok(4));
        assert_eq!(decode(&E5[..], &mut dst[..5]), Ok(4));
        assert_eq!(U5, &dst[..4]);            
    }
}