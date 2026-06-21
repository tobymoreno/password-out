use crate::{
    cli::{self, Mode},
    hotkey, overlay, providers,
};

pub fn run() -> Result<(), String> {
    let config = cli::parse_args()?;

    match config.mode {
        Mode::Listen => {
            let entries = providers::file::load_entries(&config.secrets_file)?;

            let runtime_entries = entries
                .into_iter()
                .map(|entry| hotkey::RuntimeEntry {
                    name: entry.name,
                    hotkey: entry.hotkey,
                    secret: entry.secret,
                })
                .collect();

            hotkey::listen(runtime_entries, config.clear_seconds)
        }

        Mode::Overlay(message) => {
            overlay::show_overlay(&message);
            Ok(())
        }
    }
}
