// Ed25519 Benchmarks Library
//
// This crate provides comprehensive benchmarks for Ed25519 implementations.
// Currently supports: ed25519-dalek, Firedancer (via FFI)

pub mod firedancer_ffi;

pub use curve25519_dalek;
pub use ed25519_dalek;
pub use ed25519_zebra;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firedancer_dalek_signature_compatibility() {
        use ed25519_dalek::{Signer, SigningKey};

        // Test vector: known private key
        let private_key_bytes = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];

        let message = b"Test message for Ed25519 signature compatibility";

        // Generate signature with Dalek
        let dalek_signing_key = SigningKey::from_bytes(&private_key_bytes);
        let dalek_public_key = dalek_signing_key.verifying_key();
        let dalek_signature = dalek_signing_key.sign(message);

        // Generate signature with Firedancer
        let fd_public_key = firedancer_ffi::public_from_private(&private_key_bytes)
            .expect("Firedancer public key generation failed");
        let fd_signature = firedancer_ffi::sign(message, &fd_public_key, &private_key_bytes)
            .expect("Firedancer signing failed");

        // Check that public keys match
        assert_eq!(
            dalek_public_key.as_bytes(),
            &fd_public_key,
            "Public keys from Dalek and Firedancer should match"
        );

        // Check that signatures match
        assert_eq!(
            dalek_signature.to_bytes(),
            fd_signature,
            "Signatures from Dalek and Firedancer should match for the same message and key"
        );

        // Verify Firedancer signature with Dalek
        use ed25519_dalek::Verifier;
        let dalek_verify_result = dalek_public_key.verify(
            message,
            &ed25519_dalek::Signature::from_bytes(&fd_signature),
        );
        assert!(
            dalek_verify_result.is_ok(),
            "Dalek should verify Firedancer signature"
        );

        // Verify Dalek signature with Firedancer
        let fd_verify_result =
            firedancer_ffi::verify(message, &dalek_signature.to_bytes(), &fd_public_key);
        assert!(
            fd_verify_result.is_ok(),
            "Firedancer should verify Dalek signature"
        );
    }

    #[test]
    fn test_multiple_messages_signature_compatibility() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::RngCore;

        let mut rng = rand::rngs::OsRng;

        // Test with 10 different random messages and keys
        for i in 0..10 {
            let mut private_key_bytes = [0u8; 32];
            rng.fill_bytes(&mut private_key_bytes);

            let message = format!("Test message number {}", i);

            // Generate signature with Dalek
            let dalek_signing_key = SigningKey::from_bytes(&private_key_bytes);
            let dalek_public_key = dalek_signing_key.verifying_key();
            let dalek_signature = dalek_signing_key.sign(message.as_bytes());

            // Generate signature with Firedancer
            let fd_public_key = firedancer_ffi::public_from_private(&private_key_bytes)
                .expect("Firedancer public key generation failed");
            let fd_signature =
                firedancer_ffi::sign(message.as_bytes(), &fd_public_key, &private_key_bytes)
                    .expect("Firedancer signing failed");

            // Check that public keys match
            assert_eq!(
                dalek_public_key.as_bytes(),
                &fd_public_key,
                "Public keys should match for message {}",
                i
            );

            // Check that signatures match
            assert_eq!(
                dalek_signature.to_bytes(),
                fd_signature,
                "Signatures should match for message {}",
                i
            );
        }
    }

    #[test]
    fn test_cross_verification() {
        use ed25519_dalek::{Signer, SigningKey, Verifier};

        let private_key_bytes = [42u8; 32];
        let message = b"Cross-verification test";

        // Create keys with both implementations
        let dalek_signing_key = SigningKey::from_bytes(&private_key_bytes);
        let dalek_public_key = dalek_signing_key.verifying_key();

        let fd_public_key = firedancer_ffi::public_from_private(&private_key_bytes)
            .expect("Firedancer public key generation failed");

        // Sign with Dalek, verify with Firedancer
        let dalek_signature = dalek_signing_key.sign(message);
        let fd_verify_dalek_sig =
            firedancer_ffi::verify(message, &dalek_signature.to_bytes(), &fd_public_key);
        assert!(
            fd_verify_dalek_sig.is_ok(),
            "Firedancer should verify Dalek signature"
        );

        // Sign with Firedancer, verify with Dalek
        let fd_signature = firedancer_ffi::sign(message, &fd_public_key, &private_key_bytes)
            .expect("Firedancer signing failed");
        let dalek_verify_fd_sig = dalek_public_key.verify(
            message,
            &ed25519_dalek::Signature::from_bytes(&fd_signature),
        );
        assert!(
            dalek_verify_fd_sig.is_ok(),
            "Dalek should verify Firedancer signature"
        );
    }
}
