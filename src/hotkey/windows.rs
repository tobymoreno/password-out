use super::RuntimeEntry;
use crate::clipboard;

use std::collections::HashMap;
use std::io::{self, Write};
use std::mem::zeroed;
use std::process::{Command, Stdio};
use std::ptr::null_mut;
use std::time::Instant;

use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, MOD_WIN, RegisterHotKey, UnregisterHotKey, VK_F1,
};

use windows_sys::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

#[derive(Debug, Clone, Copy)]
struct ParsedHotkey {
    modifiers: u32,
    virtual_key: u32,
}

fn parse_hotkey(input: &str) -> Result<ParsedHotkey, String> {
    let canonical = canonicalize(input)?;

    let mut modifiers = 0_u32;
    let mut virtual_key: Option<u32> = None;

    for part in canonical.split('+') {
        match part {
            "CTRL" => modifiers |= MOD_CONTROL,
            "ALT" => modifiers |= MOD_ALT,
            "SHIFT" => modifiers |= MOD_SHIFT,
            "META" => modifiers |= MOD_WIN,

            token => {
                if virtual_key.is_some() {
                    return Err("hotkey contains more than one primary key".to_string());
                }

                virtual_key = Some(parse_virtual_key(token)?);
            }
        }
    }

    if modifiers == 0 {
        return Err(format!("hotkey '{input}' requires at least one modifier"));
    }

    let virtual_key =
        virtual_key.ok_or_else(|| format!("hotkey '{input}' requires one primary key"))?;

    Ok(ParsedHotkey {
        modifiers: modifiers | MOD_NOREPEAT,
        virtual_key,
    })
}

fn parse_virtual_key(token: &str) -> Result<u32, String> {
    if token.len() == 1 {
        let character = token
            .chars()
            .next()
            .ok_or_else(|| "missing primary key".to_string())?;

        if character.is_ascii_alphanumeric() {
            return Ok(character.to_ascii_uppercase() as u32);
        }
    }

    if let Some(number_text) = token.strip_prefix('F') {
        let number = number_text
            .parse::<u32>()
            .map_err(|_| format!("invalid function key: {token}"))?;

        if (1..=12).contains(&number) {
            return Ok(VK_F1 as u32 + number - 1);
        }
    }

    Err(format!("unsupported hotkey key: {token}"))
}

pub fn canonicalize(input: &str) -> Result<String, String> {
    let mut has_control = false;
    let mut has_alt = false;
    let mut has_shift = false;
    let mut has_meta = false;
    let mut key: Option<String> = None;

    for raw_part in input.split('+') {
        let part = raw_part.trim().to_ascii_uppercase();

        if part.is_empty() {
            return Err("hotkey contains an empty token".to_string());
        }

        match part.as_str() {
            "CTRL" | "CONTROL" => {
                has_control = true;
            }

            "ALT" | "OPTION" => {
                has_alt = true;
            }

            "SHIFT" => {
                has_shift = true;
            }

            "WIN" | "WINDOWS" | "SUPER" | "META" => {
                has_meta = true;
            }

            token if is_supported_primary_key(token) => {
                if key.is_some() {
                    return Err("hotkey contains more than one primary key".to_string());
                }

                key = Some(token.to_string());
            }

            other => {
                return Err(format!("unsupported hotkey token: {other}"));
            }
        }
    }

    if !has_control && !has_alt && !has_shift && !has_meta {
        return Err("hotkey requires at least one modifier".to_string());
    }

    let key = key.ok_or_else(|| "hotkey requires one primary key".to_string())?;

    let mut parts = Vec::new();

    if has_control {
        parts.push("CTRL".to_string());
    }

    if has_alt {
        parts.push("ALT".to_string());
    }

    if has_shift {
        parts.push("SHIFT".to_string());
    }

    if has_meta {
        parts.push("META".to_string());
    }

    parts.push(key);

    Ok(parts.join("+"))
}

fn is_supported_primary_key(token: &str) -> bool {
    if token.len() == 1 {
        return token
            .chars()
            .all(|character| character.is_ascii_alphanumeric());
    }

    matches!(
        token,
        "F1" | "F2" | "F3" | "F4" | "F5" | "F6" | "F7" | "F8" | "F9" | "F10" | "F11" | "F12"
    )
}

pub fn capture() -> Result<String, String> {
    println!();
    println!("Interactive Windows hotkey capture is not implemented yet.");
    println!("Enter the chord manually, for example CTRL+ALT+G.");
    print!("Hotkey: ");

    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("failed to read hotkey: {error}"))?;

    canonicalize(input.trim())
}

pub fn test_registration(input: &str) -> Result<(), String> {
    const TEST_HOTKEY_ID: i32 = 0x4CC1;

    let parsed = parse_hotkey(input)?;

    let registered = unsafe {
        RegisterHotKey(
            null_mut(),
            TEST_HOTKEY_ID,
            parsed.modifiers,
            parsed.virtual_key,
        )
    };

    if registered == 0 {
        return Err(format!(
            "Windows rejected hotkey '{input}': {}",
            io::Error::last_os_error()
        ));
    }

    let unregistered = unsafe { UnregisterHotKey(null_mut(), TEST_HOTKEY_ID) };

    if unregistered == 0 {
        return Err(format!(
            "failed to unregister test hotkey '{input}': {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn show_overlay_helper(message: &str) {
    let executable = match std::env::current_exe() {
        Ok(path) => path,

        Err(error) => {
            eprintln!("password-out error: failed to locate current executable: {error}");
            return;
        }
    };

    let spawn_result = Command::new(executable)
        .arg("--overlay")
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Err(error) = spawn_result {
        eprintln!("password-out error: failed to spawn overlay helper: {error}");
    }
}

fn unregister_all(ids: impl Iterator<Item = i32>) {
    for id in ids {
        unsafe {
            UnregisterHotKey(null_mut(), id);
        }
    }
}

pub fn listen(entries: Vec<RuntimeEntry>, clear_seconds: u64) -> Result<(), String> {
    if entries.is_empty() {
        return Err("no PasswordOut entries were loaded".to_string());
    }

    let mut id_to_entry: HashMap<i32, RuntimeEntry> = HashMap::new();

    println!("PasswordOut listening globally...");
    println!("Registered hotkeys:");

    for (index, entry) in entries.into_iter().enumerate() {
        let id = i32::try_from(index + 1).map_err(|_| "too many hotkey entries".to_string())?;

        let parsed = parse_hotkey(&entry.hotkey)
            .map_err(|error| format!("failed parsing hotkey for '{}': {error}", entry.name))?;

        let registered =
            unsafe { RegisterHotKey(null_mut(), id, parsed.modifiers, parsed.virtual_key) };

        if registered == 0 {
            unregister_all(id_to_entry.keys().copied());

            return Err(format!(
                "failed to register hotkey '{}' for '{}': {}",
                entry.hotkey,
                entry.name,
                io::Error::last_os_error()
            ));
        }

        println!("  {:<20} {}", entry.name, entry.hotkey);

        id_to_entry.insert(id, entry);
    }

    println!();
    println!("Leave this running. Press Ctrl+C to stop.");
    println!("Click into any Windows application, press a configured hotkey, then Ctrl+V.");

    let debounce_ms: u128 = 500;
    let mut last_fire: HashMap<i32, Instant> = HashMap::new();

    loop {
        let mut message: MSG = unsafe { zeroed() };

        let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };

        if result == -1 {
            unregister_all(id_to_entry.keys().copied());

            return Err(format!(
                "Windows message loop failed: {}",
                io::Error::last_os_error()
            ));
        }

        if result == 0 {
            break;
        }

        if message.message != WM_HOTKEY {
            continue;
        }

        let id = message.wParam as i32;
        let now = Instant::now();

        if let Some(previous) = last_fire.get(&id) {
            if now.duration_since(*previous).as_millis() < debounce_ms {
                continue;
            }
        }

        last_fire.insert(id, now);

        let Some(entry) = id_to_entry.get(&id) else {
            eprintln!("password-out warning: hotkey id {id} did not match an entry");
            continue;
        };

        if let Err(error) = clipboard::copy_to_clipboard(&entry.secret) {
            eprintln!("password-out error: {error}");
            continue;
        }

        clipboard::clear_clipboard_if_matches_after(entry.secret.clone(), clear_seconds);

        println!("Copied secret for '{}'.", entry.name);

        let overlay_message = format!("Password for {} copied to clipboard", entry.name);

        show_overlay_helper(&overlay_message);
    }

    unregister_all(id_to_entry.keys().copied());

    Ok(())
}
