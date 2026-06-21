mod app;
mod cli;
mod clipboard;
mod entries;
mod hotkey;
mod overlay;
mod vault;

fn main() {
    if let Err(error) = app::run() {
        eprintln!("password-out error: {error}");
        std::process::exit(1);
    }
}
