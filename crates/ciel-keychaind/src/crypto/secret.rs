//! ============================================================================
//! ciel-keychaind - Zeroizing & Memory-Locked Secret Types
//!
//! Provides defense-in-depth memory handling for secrets:
//! - Secure zeroization: memory buffers are cleared using compiler memory fences
//!   upon `Drop` to prevent secret retention in deallocated memory.
//! - Virtual address page locking (`mlock`): prevents individual secret buffers
//!   from being swapped out to disk or captured in OS hibernate images.
//! - Redacted `Debug` formatting: prevents accidental leakage of passphrases or
//!   keys into application logs.
//!
//! ============================================================================

use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A heap-allocated byte buffer that attempts virtual memory page locking
/// (`mlock`) and strictly zeroizes all contents upon disposal.
pub struct SecureBuffer {
    data: Vec<u8>,
    is_locked: bool,
}

impl SecureBuffer {
    /// Allocates a new secure buffer from an existing byte slice.
    pub fn new(slice: &[u8]) -> Self {
        let mut data = slice.to_vec();
        let is_locked = lock_buffer(&mut data);

        Self { data, is_locked }
    }

    /// Allocates an empty secure buffer with pre-reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity);
        let is_locked = lock_buffer(&mut data);

        Self { data, is_locked }
    }

    /// Appends bytes into the locked buffer.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
        // Refresh memory lock if vector reallocation moved the buffer
        self.is_locked = lock_buffer(&mut self.data);
    }

    /// Returns whether this buffer's virtual address pages were successfully locked in RAM.
    pub fn is_memory_locked(&self) -> bool {
        self.is_locked
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Zeroize memory first
        self.data.zeroize();

        // Release mlock if previously held
        if self.is_locked && !self.data.is_empty() {
            unsafe {
                libc::munlock(
                    self.data.as_ptr() as *const libc::c_void,
                    self.data.capacity(),
                );
            }
        }
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        Self::new(&self.data)
    }
}

impl fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuffer([REDACTED {} bytes])", self.data.len())
    }
}

/// Generic wrapper that redacts `Debug` printing and zeroizes inner data on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProtectedSecret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> ProtectedSecret<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn expose(&self) -> &T {
        &self.inner
    }

    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> Deref for ProtectedSecret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for ProtectedSecret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize> fmt::Debug for ProtectedSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedSecret([REDACTED])")
    }
}

/// Helper function to invoke `libc::mlock` on a vector's backing storage.
fn lock_buffer(vec: &mut Vec<u8>) -> bool {
    let capacity = vec.capacity();
    if capacity == 0 {
        return false;
    }

    let ptr = vec.as_ptr() as *const libc::c_void;
    let res = unsafe { libc::mlock(ptr, capacity) };
    res == 0
}
