#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{clear_if_matches, copy_to_clipboard, current_text};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{clear_if_matches, copy_to_clipboard, current_text};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("PasswordOut clipboard support is currently implemented only for macOS and Windows");
