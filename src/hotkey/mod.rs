use crate::clipboard;
use crate::providers::file::SecretEntry;

use cocoa::appkit::{
    NSApp, NSApplication, NSApplicationActivationPolicyAccessory,
};
use cocoa::base::nil;

use global_hotkey::{
    hotkey::{Code, HotKey, Modifiers},
    GlobalHotKeyEvent, GlobalHotKeyManager,
};

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

fn parse_hotkey(input: &str) -> Result<HotKey, String> {
    let mut modifiers = Modifiers::empty();
    let mut key_code: Option<Code> = None;

    for raw_part in input.split('+') {
        let part = raw_part.trim().to_uppercase();

        match part.as_str() {
            "CTRL" | "CONTROL" => modifiers |= Modifiers::CONTROL,
            "ALT" | "OPTION" => modifiers |= Modifiers::ALT,
            "SHIFT" => modifiers |= Modifiers::SHIFT,
            "CMD" | "COMMAND" | "SUPER" | "META" => modifiers |= Modifiers::SUPER,

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

            other => return Err(format!("unsupported hotkey token: {}", other)),
        }
    }

    let key_code = key_code.ok_or_else(|| format!("missing key in hotkey: {}", input))?;

    if modifiers.is_empty() {
        return Err(format!("hotkey '{}' has no modifier", input));
    }

    Ok(HotKey::new(Some(modifiers), key_code))
}

fn show_overlay_helper(message: &str) {
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("passmgr error: failed to locate current exe: {}", err);
            return;
        }
    };

    let spawn_result = Command::new(exe)
        .arg("--overlay")
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/")
        .spawn();

    if let Err(err) = spawn_result {
        eprintln!("passmgr error: failed to spawn overlay helper: {}", err);
    }
}

pub fn listen(entries: Vec<SecretEntry>, clear_seconds: u64) -> Result<(), String> {
    unsafe {
        let app = NSApp();
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);
    }

    let manager = GlobalHotKeyManager::new()
        .map_err(|e| format!("failed to create hotkey manager: {e}"))?;

    let mut id_to_entry: HashMap<u32, SecretEntry> = HashMap::new();

    println!("passmgr listening globally...");
    println!("Registered hotkeys:");

    for entry in entries {
        let hotkey = parse_hotkey(&entry.hotkey)
            .map_err(|e| format!("failed parsing hotkey for '{}': {}", entry.name, e))?;

        manager
            .register(hotkey)
            .map_err(|e| format!("failed to register hotkey '{}': {e}", entry.hotkey))?;

        println!("  {:<20} {}", entry.name, entry.hotkey);

        id_to_entry.insert(hotkey.id(), entry);
    }

    println!();
    println!("Leave this running. Press Ctrl+C to stop.");
    println!("Click into any GUI app, press a configured hotkey, then Command+V.");

    let worker_entries = Arc::new(id_to_entry);

    std::thread::spawn(move || {
        let debounce_ms: u128 = 500;
        let mut last_fire: HashMap<u32, Instant> = HashMap::new();

        loop {
            match GlobalHotKeyEvent::receiver().recv() {
                Ok(event) => {
                    println!("DEBUG: hotkey event id={}", event.id);

                    let now = Instant::now();

                    if let Some(previous) = last_fire.get(&event.id) {
                        if now.duration_since(*previous).as_millis() < debounce_ms {
                            println!("DEBUG: debounce ignored event id={}", event.id);
                            continue;
                        }
                    }

                    last_fire.insert(event.id, now);

                    if let Some(entry) = worker_entries.get(&event.id) {
                        println!("DEBUG: matched {}", entry.name);

                        if let Err(err) = clipboard::copy_to_clipboard(&entry.secret) {
                            eprintln!("passmgr error: {}", err);
                            continue;
                        }

                        println!("DEBUG: copied password for {}", entry.name);

                        clipboard::clear_clipboard_if_matches_after(
                            entry.secret.clone(),
                            clear_seconds,
                        );

                        let message = format!("Password for user: {} copied to clipboard", entry.name);
                        show_overlay_helper(&message);
                    } else {
                        println!("DEBUG: event id={} did not match any entry", event.id);
                    }
                }

                Err(err) => {
                    eprintln!("passmgr error: hotkey receiver error: {}", err);
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
