#[derive(Debug, Clone)]
pub struct RuntimeEntry {
    /// Human-facing account identifier in DOMAIN\username form.
    pub account: String,
    pub hotkey: String,
    pub secret: String,
    pub expires_on: Option<String>,
    pub expiration_warning: Option<String>,
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{capture, listen};

#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub use macos::{canonicalize, test_registration};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{capture, listen};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("PasswordOut hotkey support is currently implemented only for macOS and Windows");
