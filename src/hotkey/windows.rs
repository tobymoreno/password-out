use super::RuntimeEntry;
use crate::clipboard;

use std::collections::HashMap;
use std::io;
use std::mem::zeroed;
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, MOD_WIN, RegisterHotKey,
    UnregisterHotKey, VK_CONTROL, VK_ESCAPE, VK_F1, VK_INSERT, VK_LMENU, VK_LSHIFT, VK_LWIN,
    VK_RMENU, VK_RSHIFT, VK_RWIN,
};

use windows_sys::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

const LIST_HOTKEY_ID: i32 = 0x4CC2;
const LIST_HOTKEY: &str = "CTRL+ALT+SHIFT+L";

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

fn key_was_pressed(virtual_key: i32) -> bool {
    unsafe { GetAsyncKeyState(virtual_key) & 1 != 0 }
}

fn modifier_is_down() -> bool {
    key_is_down(VK_CONTROL as i32)
        || key_is_down(VK_LMENU as i32)
        || key_is_down(VK_RMENU as i32)
        || key_is_down(VK_LSHIFT as i32)
        || key_is_down(VK_RSHIFT as i32)
        || key_is_down(VK_LWIN as i32)
        || key_is_down(VK_RWIN as i32)
}

fn captured_modifiers() -> Vec<&'static str> {
    let mut modifiers = Vec::new();

    if key_is_down(VK_CONTROL as i32) {
        modifiers.push("CTRL");
    }

    if key_is_down(VK_LMENU as i32) || key_is_down(VK_RMENU as i32) {
        modifiers.push("ALT");
    }

    if key_is_down(VK_LSHIFT as i32) || key_is_down(VK_RSHIFT as i32) {
        modifiers.push("SHIFT");
    }

    if key_is_down(VK_LWIN as i32) || key_is_down(VK_RWIN as i32) {
        modifiers.push("META");
    }

    modifiers
}

fn primary_key_name(virtual_key: i32) -> Option<String> {
    if (b'A' as i32..=b'Z' as i32).contains(&virtual_key)
        || (b'0' as i32..=b'9' as i32).contains(&virtual_key)
    {
        return char::from_u32(virtual_key as u32).map(|character| character.to_string());
    }

    let first_function_key = VK_F1 as i32;
    let last_function_key = first_function_key + 11;

    if (first_function_key..=last_function_key).contains(&virtual_key) {
        return Some(format!("F{}", virtual_key - first_function_key + 1));
    }

    None
}

fn supported_primary_keys() -> impl Iterator<Item = i32> {
    (b'A' as i32..=b'Z' as i32)
        .chain(b'0' as i32..=b'9' as i32)
        .chain(VK_F1 as i32..=VK_F1 as i32 + 11)
}

fn wait_for_keys_released() {
    while modifier_is_down()
        || supported_primary_keys().any(key_is_down)
        || key_is_down(VK_ESCAPE as i32)
    {
        thread::sleep(Duration::from_millis(20));
    }
}

fn is_reserved_hotkey(hotkey: &str) -> bool {
    hotkey.eq_ignore_ascii_case(LIST_HOTKEY)
}

fn hotkey_is_available(input: &str) -> Result<bool, String> {
    const TEST_HOTKEY_ID: i32 = 0x4CC1;

    if is_reserved_hotkey(input) {
        return Ok(false);
    }

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
        let error = io::Error::last_os_error();

        if error.raw_os_error() == Some(1409) {
            return Ok(false);
        }

        return Err(format!("Windows rejected hotkey '{input}': {error}"));
    }

    let unregistered = unsafe { UnregisterHotKey(null_mut(), TEST_HOTKEY_ID) };

    if unregistered == 0 {
        return Err(format!(
            "failed to unregister test hotkey '{input}': {}",
            io::Error::last_os_error()
        ));
    }

    Ok(true)
}

fn free_hotkey_suggestions(primary_key: &str) -> Result<Vec<String>, String> {
    let mut candidates = vec![
        format!("CTRL+ALT+SHIFT+{primary_key}"),
        format!("CTRL+SHIFT+{primary_key}"),
        format!("ALT+SHIFT+{primary_key}"),
        "CTRL+ALT+F9".to_string(),
        "CTRL+ALT+F10".to_string(),
        "CTRL+ALT+F11".to_string(),
        "CTRL+ALT+SHIFT+1".to_string(),
        "CTRL+ALT+SHIFT+2".to_string(),
        "CTRL+ALT+SHIFT+3".to_string(),
    ];

    candidates.dedup();

    let mut available = Vec::new();

    for candidate in candidates {
        if hotkey_is_available(&candidate)? {
            available.push(candidate);

            if available.len() == 3 {
                break;
            }
        }
    }

    Ok(available)
}

pub fn capture() -> Result<String, String> {
    println!();
    println!("Press the desired hotkey combination.");
    println!("Supported primary keys: A-Z, 0-9, and F1-F12.");
    println!("Press Esc to cancel.");

    wait_for_keys_released();

    loop {
        if key_was_pressed(VK_ESCAPE as i32) {
            wait_for_keys_released();
            return Err("hotkey capture cancelled".to_string());
        }

        for virtual_key in supported_primary_keys() {
            if !key_was_pressed(virtual_key) {
                continue;
            }

            let primary_key = primary_key_name(virtual_key)
                .ok_or_else(|| "failed to identify captured primary key".to_string())?;

            let modifiers = captured_modifiers();

            if modifiers.is_empty() {
                println!("A hotkey requires at least one modifier. Try again.");
                wait_for_keys_released();
                continue;
            }

            let captured = format!("{}+{primary_key}", modifiers.join("+"));
            let captured = canonicalize(&captured)?;

            println!("Captured: {captured}");

            wait_for_keys_released();

            if hotkey_is_available(&captured)? {
                println!("Hotkey is available.");
                return Ok(captured);
            }

            if is_reserved_hotkey(&captured) {
                println!("That hotkey is reserved by PasswordOut.");
            } else {
                println!("That hotkey is already registered by Windows or another application.");
            }

            let suggestions = free_hotkey_suggestions(&primary_key)?;

            if suggestions.is_empty() {
                println!("No free recommendations were found. Press another combination.");
            } else {
                println!("Available suggestions:");

                for (index, suggestion) in suggestions.iter().enumerate() {
                    println!("  {}. {}", index + 1, suggestion);
                }

                println!("Press one of these combinations, or choose another.");
            }

            break;
        }

        thread::sleep(Duration::from_millis(10));
    }
}

#[allow(dead_code)]
pub fn test_registration(input: &str) -> Result<(), String> {
    if hotkey_is_available(input)? {
        Ok(())
    } else {
        Err(format!(
            "Windows rejected hotkey '{input}': it is already registered or reserved"
        ))
    }
}

fn spawn_overlay_helper(message: &str) -> Option<Child> {
    let executable = match std::env::current_exe() {
        Ok(path) => path,

        Err(error) => {
            eprintln!("password-out error: failed to locate current executable: {error}");
            return None;
        }
    };

    match Command::new(executable)
        .arg("--overlay")
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => Some(child),

        Err(error) => {
            eprintln!("password-out error: failed to spawn overlay helper: {error}");
            None
        }
    }
}

fn show_overlay_helper(message: &str) {
    let _ = spawn_overlay_helper(message);
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

fn start_clipboard_monitor(state: SharedClipboardState) {
    thread::spawn(move || {
        let mut previous_v_down = false;
        let mut previous_insert_down = false;

        loop {
            let control_down = key_is_down(VK_CONTROL as i32);
            let shift_down = key_is_down(VK_LSHIFT as i32) || key_is_down(VK_RSHIFT as i32);
            let v_down = key_is_down('V' as i32);
            let insert_down = key_is_down(VK_INSERT as i32);

            let paste_pressed = (control_down && v_down && !previous_v_down)
                || (shift_down && insert_down && !previous_insert_down);

            previous_v_down = v_down;
            previous_insert_down = insert_down;

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

                    Ok(_) if paste_pressed => {
                        let paste_state = Arc::clone(&state);

                        thread::spawn(move || {
                            thread::sleep(Duration::from_millis(125));

                            let should_clear = paste_state
                                .lock()
                                .ok()
                                .and_then(|active| {
                                    active.as_ref().map(|current| {
                                        current.generation == generation && current.secret == secret
                                    })
                                })
                                .unwrap_or(false);

                            if should_clear {
                                let _ = clipboard::clear_if_matches(&secret);
                                deactivate_if_generation_matches(&paste_state, generation);
                            }
                        });
                    }

                    Ok(_) | Err(_) => {}
                }
            }

            thread::sleep(Duration::from_millis(20));
        }
    });
}

fn key_is_down(virtual_key: i32) -> bool {
    unsafe { GetAsyncKeyState(virtual_key) < 0 }
}

fn hide_list_overlay_when_chord_released(mut child: Child) {
    thread::spawn(move || {
        loop {
            let control_down = key_is_down(VK_CONTROL as i32);
            let alt_down = key_is_down(VK_LMENU as i32);
            let shift_down = key_is_down(VK_LSHIFT as i32);
            let l_down = key_is_down('L' as i32);

            if !control_down && !alt_down && !shift_down && !l_down {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }

            thread::sleep(Duration::from_millis(20));
        }
    });
}

fn unregister_all(ids: impl Iterator<Item = i32>) {
    for id in ids {
        unsafe {
            UnregisterHotKey(null_mut(), id);
        }
    }
}

fn build_entry_list_overlay(entries: &[RuntimeEntry]) -> String {
    let mut message = String::from("PasswordOut entries:");

    for entry in entries {
        message.push('\n');
        message.push_str(&format!("{:<20} {}", entry.name, entry.hotkey));
    }

    message
}

pub fn listen(entries: Vec<RuntimeEntry>, clear_seconds: u64) -> Result<(), String> {
    if entries.is_empty() {
        return Err("no PasswordOut entries were loaded".to_string());
    }

    let clipboard_state: SharedClipboardState = Arc::new(Mutex::new(None));
    start_clipboard_monitor(Arc::clone(&clipboard_state));

    let list_overlay_message = build_entry_list_overlay(&entries);
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

    let list_hotkey = parse_hotkey(LIST_HOTKEY)?;

    let list_registered = unsafe {
        RegisterHotKey(
            null_mut(),
            LIST_HOTKEY_ID,
            list_hotkey.modifiers,
            list_hotkey.virtual_key,
        )
    };

    if list_registered == 0 {
        unregister_all(id_to_entry.keys().copied());

        return Err(format!(
            "failed to register entry-list hotkey '{LIST_HOTKEY}': {}",
            io::Error::last_os_error()
        ));
    }

    println!("  {:<20} {}", "show entry list", LIST_HOTKEY);
    println!();
    println!("Leave this running. Press Ctrl+C to stop.");
    println!("Hold {LIST_HOTKEY} to show available entries.");
    println!("Release the chord to hide the entry list.");
    println!("Click into any Windows application, press a credential hotkey, then Ctrl+V.");

    let debounce_ms: u128 = 500;
    let mut last_fire: HashMap<i32, Instant> = HashMap::new();

    loop {
        let mut message: MSG = unsafe { zeroed() };

        let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };

        if result == -1 {
            unregister_all(id_to_entry.keys().copied());
            unsafe {
                UnregisterHotKey(null_mut(), LIST_HOTKEY_ID);
            }

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

        if id == LIST_HOTKEY_ID {
            if let Some(child) = spawn_overlay_helper(&list_overlay_message) {
                hide_list_overlay_when_chord_released(child);
            }

            continue;
        }

        let Some(entry) = id_to_entry.get(&id) else {
            eprintln!("password-out warning: hotkey id {id} did not match an entry");
            continue;
        };

        if let Err(error) = clipboard::copy_to_clipboard(&entry.secret) {
            eprintln!("password-out error: {error}");
            continue;
        }

        activate_clipboard_secret(&clipboard_state, entry.secret.clone(), clear_seconds);

        println!("Copied secret for '{}'.", entry.name);

        let overlay_message = format!("Password for {} copied to clipboard", entry.name);

        show_overlay_helper(&overlay_message);
    }

    unregister_all(id_to_entry.keys().copied());

    unsafe {
        UnregisterHotKey(null_mut(), LIST_HOTKEY_ID);
    }

    Ok(())
}
