use std::{thread, time::Duration};

pub fn copy_to_clipboard(value: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("failed to open Windows clipboard: {error}"))?;

    clipboard
        .set_text(value.to_string())
        .map_err(|error| format!("failed to write Windows clipboard: {error}"))
}

pub fn clear_clipboard_if_matches_after(expected: String, clear_seconds: u64) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(clear_seconds));

        let Ok(mut clipboard) = arboard::Clipboard::new() else {
            return;
        };

        let Ok(current_value) = clipboard.get_text() else {
            return;
        };

        if current_value == expected {
            let _ = clipboard.set_text(String::new());
        }
    });
}
