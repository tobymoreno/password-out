use super::RuntimeEntry;
use crate::clipboard;
use cocoa::appkit::{NSApp, NSApplication, NSApplicationActivationPolicyAccessory};
use cocoa::base::nil;
use global_hotkey::{
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
    hotkey::{Code, HotKey, Modifiers},
};
use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LIST_HOTKEY: &str = "CTRL+ALT+SHIFT+L";
const CLEAR_HOTKEY: &str = "CTRL+ALT+SPACE";

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
            "F1" => key_code = Some(Code::F1),
            "F2" => key_code = Some(Code::F2),
            "F3" => key_code = Some(Code::F3),
            "F4" => key_code = Some(Code::F4),
            "F5" => key_code = Some(Code::F5),
            "F6" => key_code = Some(Code::F6),
            "F7" => key_code = Some(Code::F7),
            "F8" => key_code = Some(Code::F8),
            "F9" => key_code = Some(Code::F9),
            "F10" => key_code = Some(Code::F10),
            "F11" => key_code = Some(Code::F11),
            "F12" => key_code = Some(Code::F12),
            "SPACE" => key_code = Some(Code::Space),
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
            "CTRL" | "CONTROL" => has_control = true,
            "ALT" | "OPTION" => has_alt = true,
            "SHIFT" => has_shift = true,
            "CMD" | "COMMAND" | "SUPER" | "META" => has_meta = true,
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
        "F1" | "F2"
            | "F3"
            | "F4"
            | "F5"
            | "F6"
            | "F7"
            | "F8"
            | "F9"
            | "F10"
            | "F11"
            | "F12"
            | "SPACE"
    )
}

fn native_display_name(canonical: &str) -> String {
    canonical
        .split('+')
        .map(|part| match part {
            "CTRL" => "Control".to_string(),
            "ALT" => "Option".to_string(),
            "SHIFT" => "Shift".to_string(),
            "META" => "Command".to_string(),
            key => key.to_string(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

fn prompt_hotkey() -> Result<String, String> {
    print!("Hotkey: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("failed to read hotkey: {error}"))?;

    let input = input.trim();

    if input.is_empty() {
        return Err("hotkey cannot be empty".to_string());
    }

    Ok(input.to_string())
}

pub fn capture() -> Result<String, String> {
    println!();
    println!("Enter the global hotkey using canonical labels.");
    println!("Modifiers: CTRL, ALT, SHIFT, META");
    println!("Primary keys: A-Z, 0-9, and F1-F12");
    println!("Examples:");
    println!("  CTRL+ALT+1");
    println!("  META+SHIFT+P");
    println!();

    loop {
        let input = prompt_hotkey()?;

        let canonical = match canonicalize(&input) {
            Ok(value) => value,
            Err(error) => {
                println!("Invalid hotkey: {error}");
                println!("Try again.");
                println!();
                continue;
            }
        };

        let display = native_display_name(&canonical);

        println!("Canonical: {canonical}");
        println!("macOS display: {display}");
        println!("Checking availability...");

        match test_registration(&canonical) {
            Ok(()) => {
                println!("PasswordOut successfully registered this chord.");
                return Ok(canonical);
            }
            Err(error) => {
                println!("The operating system rejected this chord: {error}");
                println!("Enter another hotkey.");
                println!();
            }
        }
    }
}

pub fn test_registration(input: &str) -> Result<(), String> {
    let canonical = canonicalize(input)?;

    if canonical.eq_ignore_ascii_case(LIST_HOTKEY) {
        return Err(format!(
            "hotkey '{LIST_HOTKEY}' is reserved for showing the PasswordOut entry list"
        ));
    }

    let hotkey = parse_hotkey(&canonical)?;

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

fn spawn_overlay_helper(message: &str, persistent: bool) -> Option<Child> {
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("password-out error: failed to locate current executable: {error}");
            return None;
        }
    };

    let mut command = Command::new(executable);

    command
        .arg("--overlay")
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/")
        .process_group(0);

    if persistent {
        command.env("PASSWORD_OUT_OVERLAY_PERSISTENT", "1");
    }

    match command.spawn() {
        Ok(child) => Some(child),
        Err(error) => {
            eprintln!("password-out error: failed to spawn overlay helper: {error}");
            None
        }
    }
}

fn show_overlay_helper(message: &str) {
    let _ = spawn_overlay_helper(message, false);
}

fn show_countdown_helper(clear_seconds: u64) -> Option<Child> {
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("password-out error: failed to locate current executable: {error}");
            return None;
        }
    };

    match Command::new(executable)
        .arg("--countdown")
        .arg(clear_seconds.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/")
        .process_group(0)
        .spawn()
    {
        Ok(child) => Some(child),
        Err(error) => {
            eprintln!("password-out error: failed to spawn countdown helper: {error}");
            None
        }
    }
}

static NEXT_CLIPBOARD_GENERATION: AtomicU64 = AtomicU64::new(1);

struct ActiveClipboardSecret {
    generation: u64,
    secret: String,
    countdown: Option<Child>,
}

type SharedClipboardState = Arc<Mutex<Option<ActiveClipboardSecret>>>;

fn stop_countdown(countdown: &mut Option<Child>) {
    if let Some(mut child) = countdown.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn deactivate_if_generation_matches(state: &SharedClipboardState, generation: u64) {
    let Ok(mut active) = state.lock() else {
        return;
    };

    let Some(current) = active.as_mut() else {
        return;
    };

    if current.generation != generation {
        return;
    }

    stop_countdown(&mut current.countdown);
    *active = None;
}

fn activate_clipboard_secret(state: &SharedClipboardState, secret: String, clear_seconds: u64) {
    let generation = NEXT_CLIPBOARD_GENERATION.fetch_add(1, Ordering::Relaxed);
    let countdown = show_countdown_helper(clear_seconds);

    if let Ok(mut active) = state.lock() {
        if let Some(previous) = active.as_mut() {
            stop_countdown(&mut previous.countdown);
        }

        *active = Some(ActiveClipboardSecret {
            generation,
            secret: secret.clone(),
            countdown,
        });
    }

    let timeout_state = Arc::clone(state);

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(clear_seconds));

        let should_clear = timeout_state
            .lock()
            .ok()
            .and_then(|active| {
                active
                    .as_ref()
                    .map(|current| current.generation == generation && current.secret == secret)
            })
            .unwrap_or(false);

        if !should_clear {
            return;
        }

        let _ = clipboard::clear_if_matches(&secret);
        deactivate_if_generation_matches(&timeout_state, generation);
    });
}

fn clear_active_clipboard(state: &SharedClipboardState) {
    let snapshot = state.lock().ok().and_then(|active| {
        active
            .as_ref()
            .map(|current| (current.generation, current.secret.clone()))
    });

    let Some((generation, secret)) = snapshot else {
        return;
    };

    match clipboard::clear_if_matches(&secret) {
        Ok(true) => {
            println!("Cleared active PasswordOut secret from clipboard.");
            deactivate_if_generation_matches(state, generation);
        }
        Ok(false) => {
            deactivate_if_generation_matches(state, generation);
        }
        Err(error) => {
            eprintln!("password-out error: {error}");
        }
    }
}

fn start_clipboard_replacement_monitor(state: SharedClipboardState) {
    thread::spawn(move || {
        loop {
            let snapshot = state.lock().ok().and_then(|active| {
                active
                    .as_ref()
                    .map(|current| (current.generation, current.secret.clone()))
            });

            if let Some((generation, secret)) = snapshot {
                match clipboard::current_text() {
                    Ok(current) if current != secret => {
                        deactivate_if_generation_matches(&state, generation);
                    }
                    Ok(_) | Err(_) => {}
                }
            }

            thread::sleep(Duration::from_millis(50));
        }
    });
}

fn build_entry_list_overlay(entries: &[RuntimeEntry]) -> String {
    let mut message = String::from("PasswordOut entries:");

    for entry in entries {
        message.push('\n');

        match (
            entry.expires_on.as_deref(),
            entry.expiration_warning.as_deref(),
        ) {
            (Some(expires_on), Some(warning)) => {
                message.push_str(&format!(
                    "{:<28} {:<18} expires {} — {}",
                    entry.account, entry.hotkey, expires_on, warning
                ));
            }
            (Some(expires_on), None) => {
                message.push_str(&format!(
                    "{:<28} {:<18} expires {}",
                    entry.account, entry.hotkey, expires_on
                ));
            }
            (None, _) => {
                message.push_str(&format!("{:<28} {}", entry.account, entry.hotkey));
            }
        }
    }

    message
}

pub fn listen(entries: Vec<RuntimeEntry>, clear_seconds: u64) -> Result<(), String> {
    if entries.is_empty() {
        return Err("no PasswordOut entries were loaded".to_string());
    }

    unsafe {
        let app = NSApp();
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);
    }

    let manager = GlobalHotKeyManager::new()
        .map_err(|error| format!("failed to create hotkey manager: {error}"))?;

    let clipboard_state: SharedClipboardState = Arc::new(Mutex::new(None));
    start_clipboard_replacement_monitor(Arc::clone(&clipboard_state));

    let list_overlay_message = build_entry_list_overlay(&entries);
    let list_hotkey = parse_hotkey(LIST_HOTKEY)?;
    let list_hotkey_id = list_hotkey.id();
    let clear_hotkey = parse_hotkey(CLEAR_HOTKEY)?;
    let clear_hotkey_id = clear_hotkey.id();

    let mut id_to_entry: HashMap<u32, RuntimeEntry> = HashMap::new();

    println!("PasswordOut listening globally...");
    println!("Registered hotkeys:");

    for entry in entries {
        let canonical = canonicalize(&entry.hotkey)?;

        if canonical.eq_ignore_ascii_case(LIST_HOTKEY) {
            return Err(format!(
                "hotkey '{LIST_HOTKEY}' is reserved for showing the entry list"
            ));
        }

        let hotkey = parse_hotkey(&canonical)
            .map_err(|error| format!("failed parsing hotkey for '{}': {error}", entry.account))?;

        manager
            .register(hotkey)
            .map_err(|error| format!("failed to register hotkey '{}': {error}", entry.hotkey))?;

        println!("  {:<20} {}", entry.account, canonical);
        id_to_entry.insert(hotkey.id(), entry);
    }

    manager.register(list_hotkey).map_err(|error| {
        format!("failed to register entry-list hotkey '{LIST_HOTKEY}': {error}")
    })?;

    manager.register(clear_hotkey).map_err(|error| {
        format!("failed to register clipboard-clear hotkey '{CLEAR_HOTKEY}': {error}")
    })?;

    println!("  {:<20} {}", "show entry list", LIST_HOTKEY);
    println!("  {:<20} {}", "clear active secret", CLEAR_HOTKEY);
    println!();
    println!("Leave this running. Press Ctrl+C to stop.");
    println!("Hold {LIST_HOTKEY} to show available entries.");
    println!("Release the chord to hide the entry list.");
    println!("Click into any GUI application, press a credential hotkey, then Command+V.");
    println!("Press {CLEAR_HOTKEY} to clear an active PasswordOut secret immediately.");

    let worker_entries = Arc::new(id_to_entry);
    let worker_clipboard_state = Arc::clone(&clipboard_state);

    thread::spawn(move || {
        let debounce_ms: u128 = 500;
        let mut last_fire: HashMap<u32, Instant> = HashMap::new();
        let mut list_overlay_child: Option<(Child, Instant)> = None;

        loop {
            match GlobalHotKeyEvent::receiver().recv() {
                Ok(event) => {
                    if event.id == clear_hotkey_id {
                        if event.state == HotKeyState::Pressed {
                            clear_active_clipboard(&worker_clipboard_state);
                        }

                        continue;
                    }

                    if event.id == list_hotkey_id {
                        match event.state {
                            HotKeyState::Pressed => {
                                let should_spawn = match list_overlay_child.as_mut() {
                                    Some((child, _)) => match child.try_wait() {
                                        Ok(Some(_)) => true,
                                        Ok(None) => false,
                                        Err(_) => true,
                                    },
                                    None => true,
                                };

                                if should_spawn {
                                    if let Some(child) =
                                        spawn_overlay_helper(&list_overlay_message, true)
                                    {
                                        list_overlay_child = Some((child, Instant::now()));
                                    }
                                }
                            }
                            HotKeyState::Released => {
                                if let Some((mut child, started_at)) = list_overlay_child.take() {
                                    // Give AppKit a brief startup window so a quick
                                    // press/release still becomes visible before the
                                    // helper is terminated.
                                    const MIN_VISIBLE_TIME: Duration = Duration::from_millis(150);

                                    let elapsed = started_at.elapsed();

                                    if elapsed < MIN_VISIBLE_TIME {
                                        thread::sleep(MIN_VISIBLE_TIME - elapsed);
                                    }

                                    let _ = child.kill();
                                    let _ = child.wait();
                                }
                            }
                        }

                        continue;
                    }

                    if event.state != HotKeyState::Pressed {
                        continue;
                    }

                    let now = Instant::now();

                    if let Some(previous) = last_fire.get(&event.id)
                        && now.duration_since(*previous).as_millis() < debounce_ms
                    {
                        continue;
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

                    activate_clipboard_secret(
                        &worker_clipboard_state,
                        entry.secret.clone(),
                        clear_seconds,
                    );

                    println!("Copied secret for '{}'.", entry.account);

                    let message = match (
                        entry.expires_on.as_deref(),
                        entry.expiration_warning.as_deref(),
                    ) {
                        (Some(expires_on), Some(warning)) => format!(
                            "Password for {} copied to clipboard\nExpires: {}\n{}",
                            entry.account, expires_on, warning
                        ),
                        (Some(expires_on), None) => format!(
                            "Password for {} copied to clipboard\nExpires: {}",
                            entry.account, expires_on
                        ),
                        (None, _) => {
                            format!("Password for {} copied to clipboard", entry.account)
                        }
                    };

                    show_overlay_helper(&message);
                }
                Err(error) => {
                    if let Some((mut child, _)) = list_overlay_child.take() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }

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
