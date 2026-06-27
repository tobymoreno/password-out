pub fn copy_to_clipboard(value: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("failed to open Windows clipboard: {error}"))?;

    clipboard
        .set_text(value.to_string())
        .map_err(|error| format!("failed to write Windows clipboard: {error}"))
}

pub fn current_text() -> Result<String, String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("failed to open Windows clipboard: {error}"))?;

    clipboard
        .get_text()
        .map_err(|error| format!("failed to read Windows clipboard: {error}"))
}

pub fn clear_if_matches(expected: &str) -> Result<bool, String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("failed to open Windows clipboard: {error}"))?;

    let current_value = clipboard
        .get_text()
        .map_err(|error| format!("failed to read Windows clipboard: {error}"))?;

    if current_value != expected {
        return Ok(false);
    }

    clipboard
        .set_text(String::new())
        .map_err(|error| format!("failed to clear Windows clipboard: {error}"))?;

    Ok(true)
}
