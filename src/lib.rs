// src/lib.rs

extern crate self as password_out;

#[path = "entries.rs"]
pub mod entries;

pub mod certificate;
pub mod smartcard;
pub mod vault_core;

pub use vault_core as vault;
