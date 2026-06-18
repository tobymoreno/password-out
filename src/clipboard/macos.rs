use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

pub fn copy_to_clipboard(secret: &str) -> Result<(), String> {
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start pbcopy: {}", e))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| "failed to open pbcopy stdin".to_string())?;

    stdin
        .write_all(secret.as_bytes())
        .map_err(|e| format!("failed to write to pbcopy: {}", e))?;

    let status = child
        .wait()
        .map_err(|e| format!("failed waiting for pbcopy: {}", e))?;

    if !status.success() {
        return Err(format!("pbcopy failed with status: {}", status));
    }

    Ok(())
}

fn read_clipboard() -> Option<String> {
    let output = Command::new("pbpaste").output().ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn clear_clipboard() {
    let _ = Command::new("sh")
        .arg("-c")
        .arg("printf '' | pbcopy")
        .status();
}

pub fn clear_clipboard_if_matches_after(secret: String, seconds: u64) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));

        if let Some(current) = read_clipboard() {
            if current == secret {
                clear_clipboard();
            }
        }
    });
}
