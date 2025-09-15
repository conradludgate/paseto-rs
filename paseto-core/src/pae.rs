pub trait WriteBytes {
    fn write(&mut self, slice: &[u8]);
}

impl<W: WriteBytes> WriteBytes for &mut W {
    fn write(&mut self, slice: &[u8]) {
        W::write(self, slice);
    }
}

pub fn pre_auth_encode<const N: usize>(pieces: [&[&[u8]]; N], mut out: impl WriteBytes) {
    let len = N as u64;
    out.write(&len.to_le_bytes());
    for piece in pieces {
        let len: u64 = piece.iter().map(|x| x.len() as u64).sum();
        out.write(&len.to_le_bytes());
        for x in piece {
            out.write(x);
        }
    }
}

#[cfg(test)]
mod tests {
    impl super::WriteBytes for Vec<u8> {
        fn write(&mut self, slice: &[u8]) {
            self.extend_from_slice(slice)
        }
    }

    fn pae_vec<const N: usize>(pieces: [&[&[u8]]; N]) -> Vec<u8> {
        let mut vec = Vec::new();
        super::pre_auth_encode(pieces, &mut vec);
        vec
    }

    #[test]
    fn test() {
        let v = pae_vec([]);
        assert_eq!(v, b"\x00\x00\x00\x00\x00\x00\x00\x00");

        let v = pae_vec([&[b""]]);
        assert_eq!(
            v,
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        );

        let v = pae_vec([&[b"test"]]);
        assert_eq!(
            v,
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"
        );
    }
}
