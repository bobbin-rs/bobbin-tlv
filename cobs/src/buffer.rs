pub struct Buffer<'a> {
    buf: &'a mut [u8],
    head: usize,
    tail: usize,
}

impl<'a> Buffer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Buffer { buf: buf, head: 0, tail: 0 }
    }

    pub fn from(buf: &'a mut [u8]) -> Self {
        let len = buf.len();
        Buffer { buf: buf, head: 0, tail: len }
    }

    pub fn cap(&self) -> usize {
        self.buf.len()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.tail
    }

    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.tail..]
    }

    pub fn extend(&mut self, value: usize) -> &mut Self {
        self.tail += value;
        assert!(self.tail <= self.buf.len());
        self
    }

    pub fn push(&mut self, b: u8) -> &mut Self {
        assert!(self.tail < self.buf.len());
        self.buf[self.tail] = b;
        self.tail += 1;
        self
    }

    pub fn advance(&mut self, value: usize) -> &mut Self {
        self.head += value;
        assert!(self.head <= self.tail);
        assert!(self.head <= self.buf.len());
        self
    }

    pub fn next_null(&self) -> Option<usize> {
        for i in self.head..self.tail {
            if self.buf[i] == 0 {
                return Some(i)
            }
        }
        None
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        if let Some(i) = self.next_null() {
            let head = self.head;
            self.head = i + 1;
            Some(&self.buf[head..i])
        } else {
            None
        }
    }

    pub fn compact(&mut self) -> &Self {
        if self.head == self.tail { 
            self.head = 0;
            self.tail = 0;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null() {
        let mut buf = [0u8; 64];
        let mut b = Buffer::new(&mut buf);
        assert_eq!(b.next_null(), None);
        assert_eq!(b.next_packet(), None);
    }

    #[test]
    fn test_one() {
        let tmp = [0u8; 64];
        let mut buf = [0u8; 64];
        let mut b = Buffer::new(&mut buf);
        b.extend(1);
        assert_eq!(b.len(), 1);
        assert_eq!(b.next_null(), Some(0));
        assert_eq!(b.next_packet(), Some(&tmp[..0]));
        assert_eq!(b.len(), 0);
        assert_eq!(b.next_null(), None);
        assert_eq!(b.next_packet(), None);
    }

    #[test]
    fn test_some() {
        let mut buf = [1, 2, 3, 4, 0];
        let mut b = Buffer::new(&mut buf);
        b.extend(4);
        assert_eq!(b.len(), 4);
        assert_eq!(b.next_null(), None);
        assert_eq!(b.next_packet(), None);
        b.extend(1);
        assert_eq!(b.next_null(), Some(4));
        assert_eq!(b.next_packet(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(b.next_null(), None);
        assert_eq!(b.next_packet(), None);
    }
    
}