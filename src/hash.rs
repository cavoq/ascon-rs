use crate::{permutation::State, Error};

struct Sponge {
    state: State,
    pos: usize,
}

impl Sponge {
    fn new(iv: u64) -> Self {
        let mut state = State([iv, 0, 0, 0, 0]);
        state.permute(12);
        Self { state, pos: 0 }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.state.xor_byte(self.pos, byte);
            self.pos += 1;
            if self.pos == 8 {
                self.state.permute(12);
                self.pos = 0;
            }
        }
    }

    fn pad(&mut self) {
        self.state.xor_byte(self.pos, 1);
        self.state.permute(12);
        self.pos = 0;
    }

    fn finalize(mut self) -> XofReader {
        self.pad();
        XofReader {
            state: self.state,
            pos: 0,
        }
    }
}

/// Streaming Ascon-Hash256 with a 32-byte digest.
pub struct Hash256(Sponge);

impl Default for Hash256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash256 {
    /// Start a new hash.
    pub fn new() -> Self {
        Self(Sponge::new(0x0000080100cc0002))
    }
    /// Absorb another message chunk. Empty chunks are allowed.
    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }
    /// Finish the hash, consuming the absorbing state.
    pub fn finalize(self) -> [u8; 32] {
        let mut output = [0; 32];
        self.0.finalize().read(&mut output);
        output
    }
}

/// Streaming Ascon-XOF128 with caller-selected output length.
pub struct Xof128(Sponge);

impl Default for Xof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Xof128 {
    /// Start a new XOF.
    pub fn new() -> Self {
        Self(Sponge::new(0x0000080000cc0003))
    }
    /// Absorb another message chunk.
    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }
    /// Finish absorption and start squeezing output.
    pub fn finalize(self) -> XofReader {
        self.0.finalize()
    }
}

/// Streaming Ascon-CXOF128, domain separated by a customization string.
pub struct Cxof128(Sponge);

impl Cxof128 {
    /// Start a customized XOF. Customization may contain at most 256 bytes.
    /// An empty customization still produces a different function from XOF128.
    pub fn new(customization: &[u8]) -> Result<Self, Error> {
        if customization.len() > 256 {
            return Err(Error::CustomizationTooLong);
        }
        let mut sponge = Sponge::new(0x0000080000cc0004);
        sponge.update(&((customization.len() as u64) * 8).to_le_bytes());
        sponge.update(customization);
        sponge.pad();
        Ok(Self(sponge))
    }
    /// Absorb another message chunk.
    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }
    /// Finish absorption and start squeezing output.
    pub fn finalize(self) -> XofReader {
        self.0.finalize()
    }
}

/// Squeezing state for XOF128 or CXOF128. Each read continues the output stream.
pub struct XofReader {
    state: State,
    pos: usize,
}

impl XofReader {
    /// Fill an output buffer. Empty reads are a no-op.
    pub fn read(&mut self, output: &mut [u8]) {
        for byte in output {
            if self.pos == 8 {
                self.state.permute(12);
                self.pos = 0;
            }
            *byte = self.state.byte(self.pos);
            self.pos += 1;
        }
    }
}

/// Hash a byte string using Ascon-Hash256.
pub fn hash256(message: &[u8]) -> [u8; 32] {
    let mut hash = Hash256::new();
    hash.update(message);
    hash.finalize()
}

/// Fill `output` with Ascon-XOF128 bytes. Empty output is a no-op extension.
pub fn xof128(message: &[u8], output: &mut [u8]) {
    let mut xof = Xof128::new();
    xof.update(message);
    xof.finalize().read(output);
}

/// Fill `output` with Ascon-CXOF128 bytes, using at most 256 customization bytes.
/// On error output is unchanged. Empty output is a no-op extension.
pub fn cxof128(message: &[u8], customization: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let mut xof = Cxof128::new(customization)?;
    xof.update(message);
    xof.finalize().read(output);
    Ok(())
}
