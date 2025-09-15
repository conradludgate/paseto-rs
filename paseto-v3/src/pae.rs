pub trait WriteBytes {
    fn update(&mut self, slice: &[u8]);
}

pub struct Digest<M: digest::Update>(pub M);
impl<M: digest::Update> WriteBytes for Digest<M> {
    fn update(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}

pub fn pae<W: WriteBytes, const N: usize>(pieces: [&[&[u8]]; N], mut out: W) -> W {
    out.update(&(N as u64).to_le_bytes());
    for piece in pieces {
        write_piece(piece, &mut out);
    }
    out
}

fn write_piece(piece: &[&[u8]], out: &mut impl WriteBytes) {
    let len: u64 = piece.iter().map(|x| x.len() as u64).sum();
    out.update(&len.to_le_bytes());
    for x in piece {
        out.update(x);
    }
}

#[cfg(test)]
mod tests {
    use super::{pae, WriteBytes};

    impl WriteBytes for Vec<u8> {
        fn update(&mut self, slice: &[u8]) {
            self.extend_from_slice(slice)
        }
    }

    #[test]
    fn test() {
        let v = pae([], Vec::new());
        assert_eq!(v, b"\x00\x00\x00\x00\x00\x00\x00\x00");

        let v = pae([&[b""]], Vec::new());
        assert_eq!(
            v,
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        );

        let v = pae([&[b"test"]], Vec::new());
        assert_eq!(
            v,
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"
        );
    }
}
