mod app;
mod cli;
mod clipboard;
mod hotkey;
mod overlay;
mod providers;

fn main() {
    if let Err(error) = app::run() {
        eprintln!("password-out error: {error}");
        std::process::exit(1);
    }
}
