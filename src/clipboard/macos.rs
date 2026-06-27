use std::io::Write;
use std::process::{Command, Stdio};

pub fn copy_to_clipboard(secret: &str) -> Result<(), String> {
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start pbcopy: {error}"))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| "failed to open pbcopy stdin".to_string())?;

    stdin
        .write_all(secret.as_bytes())
        .map_err(|error| format!("failed to write to pbcopy: {error}"))?;

    let status = child
        .wait()
        .map_err(|error| format!("failed waiting for pbcopy: {error}"))?;

    if !status.success() {
        return Err(format!("pbcopy failed with status: {status}"));
    }

    Ok(())
}

pub fn current_text() -> Result<String, String> {
    let output = Command::new("pbpaste")
        .output()
        .map_err(|error| format!("failed to start pbpaste: {error}"))?;

    if !output.status.success() {
        return Err(format!("pbpaste failed with status: {}", output.status));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn clear_if_matches(expected: &str) -> Result<bool, String> {
    let current = current_text()?;

    if current != expected {
        return Ok(false);
    }

    copy_to_clipboard("")?;
    Ok(true)
}
