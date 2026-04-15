use zeroize::Zeroize;
use std::ops::Deref;

/// A heap-allocated byte buffer that is zeroized on drop.
/// Cloning is intentionally not derived to prevent accidental key copies.
pub struct SecureVec(Vec<u8>);

impl SecureVec {
    pub fn new(data: Vec<u8>) -> Self {
        SecureVec(data)
    }

    pub fn zeroed(len: usize) -> Self {
        SecureVec(vec![0u8; len])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return inner bytes. Caller takes ownership of zeroization.
    pub fn into_inner(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        std::mem::swap(&mut self.0, &mut out);
        // prevent Drop from double-zeroizing
        std::mem::forget(self);
        out
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for SecureVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SecureVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for SecureVec {
    fn from(v: Vec<u8>) -> Self {
        SecureVec::new(v)
    }
}

impl std::fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureVec([REDACTED, {} bytes])", self.0.len())
    }
}