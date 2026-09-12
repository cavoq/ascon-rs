use zeroize::Zeroize;

#[derive(Clone)]
pub(crate) struct State(pub(crate) [u64; 5]);

impl Drop for State {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl State {
    pub(crate) fn byte(&self, i: usize) -> u8 {
        (self.0[i / 8] >> (8 * (i % 8))) as u8
    }

    pub(crate) fn xor_byte(&mut self, i: usize, byte: u8) {
        self.0[i / 8] ^= (byte as u64) << (8 * (i % 8));
    }

    pub(crate) fn set_byte(&mut self, i: usize, byte: u8) {
        self.xor_byte(i, self.byte(i) ^ byte);
    }

    pub(crate) fn permute(&mut self, rounds: usize) {
        const RC: [u64; 12] = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ];
        for &constant in &RC[12 - rounds..] {
            self.0[2] ^= constant;
            // Bitsliced S-box circuit, SP 800-232 Figure 3. No lookup tables.
            self.0[0] ^= self.0[4];
            self.0[4] ^= self.0[3];
            self.0[2] ^= self.0[1];
            let mut t = core::array::from_fn::<_, 5, _>(|i| {
                self.0[i] ^ ((!self.0[(i + 1) % 5]) & self.0[(i + 2) % 5])
            });
            t[1] ^= t[0];
            t[0] ^= t[4];
            t[3] ^= t[2];
            t[2] = !t[2];
            for (i, (a, b)) in [(19, 28), (61, 39), (1, 6), (10, 17), (7, 41)]
                .into_iter()
                .enumerate()
            {
                self.0[i] = t[i] ^ t[i].rotate_right(a) ^ t[i].rotate_right(b);
            }
            t.zeroize();
        }
    }
}

pub(crate) fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("internal 64-bit word"))
}
