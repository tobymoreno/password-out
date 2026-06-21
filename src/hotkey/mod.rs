#[derive(Debug, Clone)]
pub struct RuntimeEntry {
    pub name: String,
    pub hotkey: String,
    pub secret: String,
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{canonicalize, capture, listen, test_registration};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{capture, listen};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("PasswordOut hotkey support is currently implemented only for macOS and Windows");
