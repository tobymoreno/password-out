use super::RuntimeEntry;
use crate::clipboard;

use cocoa::appkit::{NSApp, NSApplication, NSApplicationActivationPolicyAccessory};
use cocoa::base::nil;

use global_hotkey::{
    GlobalHotKeyEvent, GlobalHotKeyManager,
    hotkey::{Code, HotKey, Modifiers},
};

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

fn parse_hotkey(input: &str) -> Result<HotKey, String> {
    let canonical = canonicalize(input)?;

    let mut modifiers = Modifiers::empty();
    let mut key_code: Option<Code> = None;

    for part in canonical.split('+') {
        match part {
            "CTRL" => modifiers |= Modifiers::CONTROL,
            "ALT" => modifiers |= Modifiers::ALT,
            "SHIFT" => modifiers |= Modifiers::SHIFT,
            "META" => modifiers |= Modifiers::SUPER,

            "A" => key_code = Some(Code::KeyA),
            "B" => key_code = Some(Code::KeyB),
            "C" => key_code = Some(Code::KeyC),
            "D" => key_code = Some(Code::KeyD),
            "E" => key_code = Some(Code::KeyE),
            "F" => key_code = Some(Code::KeyF),
            "G" => key_code = Some(Code::KeyG),
            "H" => key_code = Some(Code::KeyH),
            "I" => key_code = Some(Code::KeyI),
            "J" => key_code = Some(Code::KeyJ),
            "K" => key_code = Some(Code::KeyK),
            "L" => key_code = Some(Code::KeyL),
            "M" => key_code = Some(Code::KeyM),
            "N" => key_code = Some(Code::KeyN),
            "O" => key_code = Some(Code::KeyO),
            "P" => key_code = Some(Code::KeyP),
            "Q" => key_code = Some(Code::KeyQ),
            "R" => key_code = Some(Code::KeyR),
            "S" => key_code = Some(Code::KeyS),
            "T" => key_code = Some(Code::KeyT),
            "U" => key_code = Some(Code::KeyU),
            "V" => key_code = Some(Code::KeyV),
            "W" => key_code = Some(Code::KeyW),
            "X" => key_code = Some(Code::KeyX),
            "Y" => key_code = Some(Code::KeyY),
            "Z" => key_code = Some(Code::KeyZ),

            "0" => key_code = Some(Code::Digit0),
            "1" => key_code = Some(Code::Digit1),
            "2" => key_code = Some(Code::Digit2),
            "3" => key_code = Some(Code::Digit3),
            "4" => key_code = Some(Code::Digit4),
            "5" => key_code = Some(Code::Digit5),
            "6" => key_code = Some(Code::Digit6),
            "7" => key_code = Some(Code::Digit7),
            "8" => key_code = Some(Code::Digit8),
            "9" => key_code = Some(Code::Digit9),

            other => {
                return Err(format!("unsupported canonical hotkey token: {other}"));
            }
        }
    }

    let key_code = key_code.ok_or_else(|| format!("missing key in hotkey: {input}"))?;

    if modifiers.is_empty() {
        return Err(format!("hotkey '{input}' has no modifier"));
    }

    Ok(HotKey::new(Some(modifiers), key_code))
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

            "CMD" | "COMMAND" | "SUPER" | "META" => {
                has_meta = true;
            }

            token
                if token.len() == 1
                    && token
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric()) =>
            {
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

#[allow(dead_code)]
pub fn capture() -> Result<String, String> {
    Err("interactive macOS hotkey capture has not been implemented yet".to_string())
}

#[allow(dead_code)]
pub fn test_registration(input: &str) -> Result<(), String> {
    let hotkey = parse_hotkey(input)?;

    let manager = GlobalHotKeyManager::new()
        .map_err(|error| format!("failed to create hotkey manager: {error}"))?;

    manager
        .register(hotkey)
        .map_err(|error| format!("failed to register hotkey '{input}': {error}"))?;

    manager
        .unregister(hotkey)
        .map_err(|error| format!("failed to unregister hotkey '{input}': {error}"))?;

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
        .arg("overlay")
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/")
        .spawn();

    if let Err(error) = spawn_result {
        eprintln!("password-out error: failed to spawn overlay helper: {error}");
    }
}

pub fn listen(entries: Vec<RuntimeEntry>, clear_seconds: u64) -> Result<(), String> {
    unsafe {
        let app = NSApp();

        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);
    }

    let manager = GlobalHotKeyManager::new()
        .map_err(|error| format!("failed to create hotkey manager: {error}"))?;

    let mut id_to_entry: HashMap<u32, RuntimeEntry> = HashMap::new();

    println!("PasswordOut listening globally...");
    println!("Registered hotkeys:");

    for entry in entries {
        let hotkey = parse_hotkey(&entry.hotkey)
            .map_err(|error| format!("failed parsing hotkey for '{}': {error}", entry.name))?;

        manager
            .register(hotkey)
            .map_err(|error| format!("failed to register hotkey '{}': {error}", entry.hotkey))?;

        println!("  {:<20} {}", entry.name, entry.hotkey);

        id_to_entry.insert(hotkey.id(), entry);
    }

    println!();
    println!("Leave this running. Press Ctrl+C to stop.");
    println!("Click into any GUI application, press a configured hotkey, then Command+V.");

    let worker_entries = Arc::new(id_to_entry);

    std::thread::spawn(move || {
        let debounce_ms: u128 = 500;
        let mut last_fire: HashMap<u32, Instant> = HashMap::new();

        loop {
            match GlobalHotKeyEvent::receiver().recv() {
                Ok(event) => {
                    let now = Instant::now();

                    if let Some(previous) = last_fire.get(&event.id) {
                        if now.duration_since(*previous).as_millis() < debounce_ms {
                            continue;
                        }
                    }

                    last_fire.insert(event.id, now);

                    let Some(entry) = worker_entries.get(&event.id) else {
                        eprintln!(
                            "password-out warning: hotkey event {} did not match an entry",
                            event.id
                        );
                        continue;
                    };

                    if let Err(error) = clipboard::copy_to_clipboard(&entry.secret) {
                        eprintln!("password-out error: {error}");
                        continue;
                    }

                    clipboard::clear_clipboard_if_matches_after(
                        entry.secret.clone(),
                        clear_seconds,
                    );

                    let message = format!("Password for {} copied to clipboard", entry.name);

                    show_overlay_helper(&message);
                }

                Err(error) => {
                    eprintln!("password-out error: hotkey receiver error: {error}");
                    break;
                }
            }
        }
    });

    unsafe {
        let app = NSApplication::sharedApplication(nil);
        app.run();
    }

    drop(manager);
    Ok(())
}
