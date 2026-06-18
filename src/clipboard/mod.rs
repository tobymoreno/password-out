#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{clear_clipboard_if_matches_after, copy_to_clipboard};
