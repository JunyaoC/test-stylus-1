//!
//! Stylus Hello World
//!
//! The following contract implements the Counter example from Foundry.
//!
//! ```
//! contract Counter {
//!     uint256 public number;
//!     function setNumber(uint256 newNumber) public {
//!         number = newNumber;
//!     }
//!     function increment() public {
//!         number++;
//!     }
//! }
//! ```
//!
//! The program is ABI-equivalent with Solidity, which means you can call it from both Solidity and Rust.
//! To do this, run `cargo stylus export-abi`.
//!
//! Note: this code is a template-only and has not been audited.
//!

// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{
    alloy_primitives::{U256, Address},
    prelude::*,
    msg,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Sha256, Digest};

// Constants
const APP_ID: &str = "4RKXM42395.junyaoc.MIRAcam";

// Define some persistent storage using the Solidity ABI.
// `Counter` will be the entrypoint.
sol_storage! {
    #[entrypoint]
    pub struct Counter {
        uint256 number;
        mapping(address => bool) verified_attestations;
    }
}

/// Declare that `Counter` is a contract with the following external methods.
#[external]
impl Counter {
    pub fn verify_attestation(
        &mut self,
        key_id: String,
        attestation: String,
        nonce: String
    ) -> Result<bool, Vec<u8>> {
        // Decode base64 inputs
        let key_id_bytes = match BASE64.decode(key_id) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };

        let nonce_bytes = match BASE64.decode(nonce) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };

        let attestation_bytes = match BASE64.decode(attestation) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };

        // Verify rpIdHash
        let app_id_hash = Sha256::digest(APP_ID);
        let rp_id_hash = &attestation_bytes[0..32];
        if rp_id_hash != app_id_hash.as_slice() {
            return Ok(false);
        }

        // Verify sign count (should be 0 for initial attestation)
        let sign_count_bytes = &attestation_bytes[33..37];
        let sign_count = u32::from_be_bytes(sign_count_bytes.try_into().unwrap());
        if sign_count != 0 {
            return Ok(false);
        }

        // Verify AAGUID
        let aa_guid = &attestation_bytes[37..53];
        let expected_guid = b"appattestdevelop";
        if aa_guid != expected_guid {
            return Ok(false);
        }

        // Verify credId
        let cred_id_len = &attestation_bytes[53..55];
        if cred_id_len[0] != 0 || cred_id_len[1] != 32 {
            return Ok(false);
        }

        let cred_id = &attestation_bytes[55..87];
        if cred_id != key_id_bytes {
            return Ok(false);
        }

        // Mark this attestation as verified for the sender
        let sender = msg::sender();
        self.verified_attestations.setter(sender).set(true);

        Ok(true)
    }

    pub fn is_verified(&self, user: Address) -> Result<bool, Vec<u8>> {
        Ok(self.verified_attestations.getter(user).get())
    }

    // Original counter functions...
    pub fn number(&self) -> Result<U256, Vec<u8>> {
        Ok(self.number.get())
    }

    pub fn set_number(&mut self, new_number: U256) -> Result<(), Vec<u8>> {
        // Only allow verified users to set numbers
        let sender = msg::sender();
        if !self.verified_attestations.getter(sender).get() {
            return Err("User not verified".into());
        }
        
        self.number.set(new_number);
        Ok(())
    }

    pub fn increment(&mut self) -> Result<(), Vec<u8>> {
        // Only allow verified users to increment
        let sender = msg::sender();
        if !self.verified_attestations.getter(sender).get() {
            return Err("User not verified".into());
        }

        let number = self.number.get();
        self.number.set(number + U256::from(1));
        Ok(())
    }
}
