#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{clear_clipboard_if_matches_after, copy_to_clipboard};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{clear_clipboard_if_matches_after, copy_to_clipboard};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("CredChord clipboard support is currently implemented only for macOS and Windows");
