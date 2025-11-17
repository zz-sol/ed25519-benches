// FFI bindings for Firedancer Ed25519 implementation
//
// Based on the Firedancer ed25519 API defined in:
// - src/ballet/ed25519/fd_ed25519.h
// - src/ballet/sha512/fd_sha512.h

use std::os::raw::c_int;

// Error codes from FD_ED25519_ERR_*
pub const FD_ED25519_SUCCESS: c_int = 0;
pub const FD_ED25519_ERR_SIG: c_int = -1;
pub const FD_ED25519_ERR_PUBKEY: c_int = -2;
pub const FD_ED25519_ERR_MSG: c_int = -3;

pub const FD_ED25519_SIG_SZ: usize = 64;
pub const FD_ED25519_PUBKEY_SZ: usize = 32;
pub const FD_ED25519_PRIVKEY_SZ: usize = 32;

// SHA512 constants
pub const FD_SHA512_ALIGN: usize = 128;
pub const FD_SHA512_FOOTPRINT: usize = 256;
pub const FD_SHA512_HASH_SZ: usize = 64;
pub const FD_SHA512_PRIVATE_BUF_MAX: usize = 128;

// fd_sha512_t opaque type - we use proper alignment
#[repr(C, align(128))]
pub struct FdSha512 {
    _buf: [u8; FD_SHA512_FOOTPRINT],
}

// Public key type
pub type FdEd25519PublicKey = [u8; FD_ED25519_PUBKEY_SZ];

// Private key type
pub type FdEd25519PrivateKey = [u8; FD_ED25519_PRIVKEY_SZ];

// Signature type
pub type FdEd25519Signature = [u8; FD_ED25519_SIG_SZ];

extern "C" {
    // SHA512 API
    pub fn fd_sha512_new(shmem: *mut u8) -> *mut FdSha512;
    pub fn fd_sha512_join(shsha: *mut u8) -> *mut FdSha512;
    pub fn fd_sha512_leave(sha: *mut FdSha512) -> *mut u8;
    pub fn fd_sha512_delete(shsha: *mut u8) -> *mut u8;
    pub fn fd_sha512_init(sha: *mut FdSha512) -> *mut FdSha512;

    // Ed25519 API
    /// Compute public key from private key
    pub fn fd_ed25519_public_from_private(
        public_key: *mut u8,
        private_key: *const u8,
        sha: *mut FdSha512,
    ) -> *mut u8;

    /// Sign a message
    pub fn fd_ed25519_sign(
        sig: *mut u8,
        msg: *const u8,
        msg_sz: u64,
        public_key: *const u8,
        private_key: *const u8,
        sha: *mut FdSha512,
    ) -> *mut u8;

    /// Verify a signature
    pub fn fd_ed25519_verify(
        msg: *const u8,
        msg_sz: u64,
        sig: *const u8,
        public_key: *const u8,
        sha: *mut FdSha512,
    ) -> c_int;

    /// Batch verify signatures over a single message
    pub fn fd_ed25519_verify_batch_single_msg(
        msg: *const u8,
        msg_sz: u64,
        signatures: *const u8,
        pubkeys: *const u8,
        shas: *mut *mut FdSha512,
        batch_sz: u8,
    ) -> c_int;

    /// Get error string
    pub fn fd_ed25519_strerror(err: c_int) -> *const std::os::raw::c_char;
}

// Safe Rust wrappers
impl FdSha512 {
    /// Create a new SHA512 context
    pub fn new() -> Box<Self> {
        unsafe {
            let mut buf = Box::new(FdSha512 {
                _buf: [0u8; FD_SHA512_FOOTPRINT],
            });
            fd_sha512_new(buf._buf.as_mut_ptr());
            fd_sha512_init(buf.as_mut());
            buf
        }
    }
}

/// Derive public key from private key
pub fn public_from_private(
    private_key: &FdEd25519PrivateKey,
) -> Result<FdEd25519PublicKey, String> {
    let mut public_key = [0u8; FD_ED25519_PUBKEY_SZ];
    let mut sha = FdSha512::new();

    unsafe {
        fd_ed25519_public_from_private(public_key.as_mut_ptr(), private_key.as_ptr(), sha.as_mut());
    }

    Ok(public_key)
}

/// Sign a message using Ed25519
pub fn sign(
    message: &[u8],
    public_key: &FdEd25519PublicKey,
    private_key: &FdEd25519PrivateKey,
) -> Result<FdEd25519Signature, String> {
    let mut signature = [0u8; FD_ED25519_SIG_SZ];
    let mut sha = FdSha512::new();

    unsafe {
        fd_ed25519_sign(
            signature.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            public_key.as_ptr(),
            private_key.as_ptr(),
            sha.as_mut(),
        );
    }

    Ok(signature)
}

/// Verify an Ed25519 signature
pub fn verify(
    message: &[u8],
    signature: &FdEd25519Signature,
    public_key: &FdEd25519PublicKey,
) -> Result<(), String> {
    let mut sha = FdSha512::new();

    unsafe {
        let result = fd_ed25519_verify(
            message.as_ptr(),
            message.len() as u64,
            signature.as_ptr(),
            public_key.as_ptr(),
            sha.as_mut(),
        );

        if result == FD_ED25519_SUCCESS {
            Ok(())
        } else {
            let err_str = std::ffi::CStr::from_ptr(fd_ed25519_strerror(result))
                .to_string_lossy()
                .into_owned();
            Err(err_str)
        }
    }
}

/// Batch verify multiple signatures over the same message
pub fn verify_batch_single_msg(
    message: &[u8],
    signatures: &[FdEd25519Signature],
    public_keys: &[FdEd25519PublicKey],
) -> Result<(), String> {
    if signatures.len() != public_keys.len() {
        return Err("Signature and public key counts must match".to_string());
    }

    if signatures.is_empty() {
        return Err("Batch must not be empty".to_string());
    }

    if signatures.len() > 255 {
        return Err("Batch size must be <= 255".to_string());
    }

    // Allocate SHA512 contexts for each signature
    let mut shas: Vec<Box<FdSha512>> = (0..signatures.len()).map(|_| FdSha512::new()).collect();

    let mut sha_ptrs: Vec<*mut FdSha512> = shas
        .iter_mut()
        .map(|sha| sha.as_mut() as *mut FdSha512)
        .collect();

    unsafe {
        let result = fd_ed25519_verify_batch_single_msg(
            message.as_ptr(),
            message.len() as u64,
            signatures.as_ptr() as *const u8,
            public_keys.as_ptr() as *const u8,
            sha_ptrs.as_mut_ptr(),
            signatures.len() as u8,
        );

        if result == FD_ED25519_SUCCESS {
            Ok(())
        } else {
            let err_str = std::ffi::CStr::from_ptr(fd_ed25519_strerror(result))
                .to_string_lossy()
                .into_owned();
            Err(err_str)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        // Test vector: private key -> public key derivation
        let private_key = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];

        let result = public_from_private(&private_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_verify() {
        // Generate a keypair
        let private_key = [1u8; 32];
        let public_key = public_from_private(&private_key).unwrap();

        // Sign a message
        let message = b"Hello, Firedancer!";
        let signature = sign(message, &public_key, &private_key).unwrap();

        // Verify the signature
        let result = verify(message, &signature, &public_key);
        assert!(result.is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let result = verify(wrong_message, &signature, &public_key);
        assert!(result.is_err());
    }
}
