#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::show_overlay;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::show_overlay;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("CredChord overlay support is currently implemented only for macOS and Windows");
