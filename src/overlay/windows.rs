use std::io;
use std::mem::zeroed;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_VCENTER, DeleteObject,
    DrawTextW, EndPaint, GetDC, GetTextExtentPoint32W, PAINTSTRUCT, ReleaseDC, SelectObject,
    SetBkMode, SetTextColor, TRANSPARENT, UpdateWindow,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GWLP_USERDATA,
    GetClientRect, GetMessageW, GetSystemMetrics, GetWindowLongPtrW, IDC_ARROW, InvalidateRect,
    KillTimer, LWA_COLORKEY, LoadCursorW, MSG, PostQuitMessage, RegisterClassW, SM_CXSCREEN,
    SM_CYSCREEN, SW_SHOWNOACTIVATE, SetLayeredWindowAttributes, SetTimer, SetWindowLongPtrW,
    ShowWindow, TranslateMessage, WM_DESTROY, WM_NCCREATE, WM_NCDESTROY, WM_PAINT, WM_TIMER,
    WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT,
    WS_POPUP,
};

const MAX_FONT_SIZE: i32 = 120;
const MIN_FONT_SIZE: i32 = 16;
const FONT_STEP: i32 = 4;

const HORIZONTAL_PADDING: i32 = 80;
const VERTICAL_PADDING: i32 = 40;
const MIN_WIDTH: i32 = 320;
const SCREEN_MARGIN: i32 = 40;
const TOP_MARGIN: i32 = 40;

const SINGLE_LINE_DURATION_MS: u32 = 1_600;
const MULTILINE_DURATION_MS: u32 = 5_000;
const COUNTDOWN_TICK_MS: u32 = 1_000;
const CLEARED_DURATION_MS: u32 = 900;
const TIMER_ID: usize = 1;

enum OverlayMode {
    Message,
    Countdown {
        remaining_seconds: u64,
        showing_cleared: bool,
    },
}

struct OverlayState {
    text: Vec<u16>,
    font: isize,
    mode: OverlayMode,
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn green_color() -> u32 {
    255 << 8
}

fn countdown_text(remaining_seconds: u64) -> Vec<u16> {
    wide(&format!(
        "PASSWORD OUT\n\n{remaining_seconds:02} SEC\n\nAUTO CLEAR"
    ))
}

unsafe fn state_ptr(hwnd: HWND) -> *mut OverlayState {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut OverlayState }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_NCCREATE => {
            let create = lparam as *const CREATESTRUCTW;
            if create.is_null() {
                return 0;
            }

            let state = unsafe { (*create).lpCreateParams as *mut OverlayState };
            if state.is_null() {
                return 0;
            }

            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
            }

            1
        }

        WM_PAINT => {
            let mut paint: PAINTSTRUCT = unsafe { zeroed() };
            let hdc = unsafe { BeginPaint(hwnd, &mut paint) };

            if !hdc.is_null() {
                let state = unsafe { state_ptr(hwnd).as_ref() };

                if let Some(state) = state {
                    if state.font != 0 {
                        unsafe {
                            SelectObject(hdc, state.font as _);
                        }
                    }

                    unsafe {
                        SetBkMode(hdc, TRANSPARENT as i32);
                        SetTextColor(hdc, green_color());
                    }

                    let mut rect: RECT = unsafe { zeroed() };
                    unsafe {
                        GetClientRect(hwnd, &mut rect);
                    }

                    let character_count = state.text.len().saturating_sub(1) as i32;

                    unsafe {
                        DrawTextW(
                            hdc,
                            state.text.as_ptr(),
                            character_count,
                            &mut rect,
                            DT_CENTER | DT_VCENTER | DT_NOPREFIX,
                        );
                    }
                }

                unsafe {
                    EndPaint(hwnd, &paint);
                }
            }

            0
        }

        WM_TIMER => {
            if wparam != TIMER_ID {
                return 0;
            }

            let state = unsafe { state_ptr(hwnd).as_mut() };
            let Some(state) = state else {
                unsafe {
                    DestroyWindow(hwnd);
                }
                return 0;
            };

            match &mut state.mode {
                OverlayMode::Message => unsafe {
                    DestroyWindow(hwnd);
                },

                OverlayMode::Countdown {
                    remaining_seconds,
                    showing_cleared,
                } => {
                    if *showing_cleared {
                        unsafe {
                            DestroyWindow(hwnd);
                        }
                        return 0;
                    }

                    if *remaining_seconds > 0 {
                        *remaining_seconds -= 1;
                    }

                    if *remaining_seconds == 0 {
                        *showing_cleared = true;
                        state.text = wide("PASSWORD OUT\n\nCLEARED\n\nCLIPBOARD EMPTY");

                        unsafe {
                            KillTimer(hwnd, TIMER_ID);
                            SetTimer(hwnd, TIMER_ID, CLEARED_DURATION_MS, None);
                        }
                    } else {
                        state.text = countdown_text(*remaining_seconds);
                    }

                    unsafe {
                        InvalidateRect(hwnd, null(), 1);
                        UpdateWindow(hwnd);
                    }
                }
            }

            0
        }

        WM_DESTROY => {
            unsafe {
                PostQuitMessage(0);
            }
            0
        }

        WM_NCDESTROY => {
            let state = unsafe { state_ptr(hwnd) };

            if !state.is_null() {
                unsafe {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }

                let state = unsafe { Box::from_raw(state) };

                if state.font != 0 {
                    unsafe {
                        DeleteObject(state.font as _);
                    }
                }
            }

            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }

        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

pub fn show_overlay(message: &str) {
    if let Err(error) = show_message_inner(message) {
        eprintln!("password-out overlay error: {error}");
    }
}

/// Shows the first Windows countdown implementation.
///
/// The window remains fully transparent except for the green text. The same
/// window is repainted once per second, so the countdown does not flicker.
pub fn show_countdown(total_seconds: u64) {
    if total_seconds == 0 {
        return;
    }

    if let Err(error) = show_countdown_inner(total_seconds) {
        eprintln!("password-out countdown overlay error: {error}");
    }
}

fn create_font(font_name: &[u16], font_size: i32) -> Result<isize, String> {
    let font = unsafe {
        CreateFontW(
            -font_size,
            0,
            0,
            0,
            700,
            0,
            0,
            0,
            1,
            0,
            0,
            4,
            0,
            font_name.as_ptr(),
        )
    };

    if font.is_null() {
        return Err(format!(
            "failed to create overlay font: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(font as isize)
}

fn measure_lines(screen_dc: isize, font: isize, lines: &[&str]) -> Result<(i32, i32), String> {
    let previous_font = unsafe { SelectObject(screen_dc as _, font as _) };

    let mut maximum_line_width = 0;
    let mut line_height = 0;

    for line in lines {
        let line_text = wide(line);
        let mut line_size: SIZE = unsafe { zeroed() };
        let character_count = line_text.len().saturating_sub(1) as i32;

        let measured = unsafe {
            GetTextExtentPoint32W(
                screen_dc as _,
                line_text.as_ptr(),
                character_count,
                &mut line_size,
            )
        };

        if measured == 0 {
            if !previous_font.is_null() {
                unsafe {
                    SelectObject(screen_dc as _, previous_font);
                }
            }

            return Err(format!(
                "failed to measure overlay text: {}",
                io::Error::last_os_error()
            ));
        }

        maximum_line_width = maximum_line_width.max(line_size.cx);
        line_height = line_height.max(line_size.cy);
    }

    if !previous_font.is_null() {
        unsafe {
            SelectObject(screen_dc as _, previous_font);
        }
    }

    Ok((maximum_line_width, line_height))
}

fn select_font_and_size(message: &str) -> Result<(isize, i32, i32), String> {
    let font_name = wide("Segoe UI");
    let screen_width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let screen_height = unsafe { GetSystemMetrics(SM_CYSCREEN) };

    let maximum_width = (screen_width - (SCREEN_MARGIN * 2)).max(MIN_WIDTH);
    let maximum_height = (screen_height - TOP_MARGIN - SCREEN_MARGIN).max(1);

    let screen_dc = unsafe { GetDC(null_mut()) };
    if screen_dc.is_null() {
        return Err(format!(
            "failed to get screen device context: {}",
            io::Error::last_os_error()
        ));
    }

    let lines: Vec<&str> = message.lines().collect();
    let line_count = lines.len().max(1) as i32;

    let mut font_size = MAX_FONT_SIZE;

    let selected = loop {
        let candidate_font = create_font(&font_name, font_size)?;
        let measurement = measure_lines(screen_dc as isize, candidate_font, &lines);

        let (line_width, line_height) = match measurement {
            Ok(measurement) => measurement,
            Err(error) => {
                unsafe {
                    DeleteObject(candidate_font as _);
                    ReleaseDC(null_mut(), screen_dc);
                }
                return Err(error);
            }
        };

        let line_spacing = (font_size / 10).max(2);
        let text_height = (line_height * line_count) + (line_spacing * (line_count - 1).max(0));

        let required_width = line_width + HORIZONTAL_PADDING;
        let required_height = text_height + VERTICAL_PADDING;

        let width_fits = required_width <= maximum_width;
        let height_fits = required_height <= maximum_height;

        if (width_fits && height_fits) || font_size <= MIN_FONT_SIZE {
            let width = required_width.max(MIN_WIDTH).min(maximum_width);
            let height = required_height.min(maximum_height);
            break (candidate_font, width, height);
        }

        unsafe {
            DeleteObject(candidate_font as _);
        }

        font_size = (font_size - FONT_STEP).max(MIN_FONT_SIZE);
    };

    unsafe {
        ReleaseDC(null_mut(), screen_dc);
    }

    Ok(selected)
}

fn show_message_inner(message: &str) -> Result<(), String> {
    let display_duration = if message.lines().count() > 1 {
        MULTILINE_DURATION_MS
    } else {
        SINGLE_LINE_DURATION_MS
    };

    let state = OverlayState {
        text: wide(message),
        font: 0,
        mode: OverlayMode::Message,
    };

    run_overlay(state, message, display_duration)
}

fn show_countdown_inner(total_seconds: u64) -> Result<(), String> {
    let initial_message = format!("PASSWORD OUT\n\n{total_seconds:02} SEC\n\nAUTO CLEAR");

    let state = OverlayState {
        text: wide(&initial_message),
        font: 0,
        mode: OverlayMode::Countdown {
            remaining_seconds: total_seconds,
            showing_cleared: false,
        },
    };

    run_overlay(state, &initial_message, COUNTDOWN_TICK_MS)
}

fn run_overlay(
    mut state: OverlayState,
    measurement_text: &str,
    timer_interval_ms: u32,
) -> Result<(), String> {
    let class_name = wide("PasswordOutOverlayWindow");
    let instance = unsafe { GetModuleHandleW(null()) };

    if instance.is_null() {
        return Err(format!(
            "failed to get module handle: {}",
            io::Error::last_os_error()
        ));
    }

    let background_brush = unsafe { CreateSolidBrush(0) };
    if background_brush.is_null() {
        return Err(format!(
            "failed to create overlay background brush: {}",
            io::Error::last_os_error()
        ));
    }

    let window_class = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: null_mut(),
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: background_brush,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };

    let atom = unsafe { RegisterClassW(&window_class) };
    if atom == 0 {
        unsafe {
            DeleteObject(background_brush as _);
        }

        return Err(format!(
            "failed to register overlay window class: {}",
            io::Error::last_os_error()
        ));
    }

    let (font, width, height) = select_font_and_size(measurement_text)?;
    state.font = font;

    let screen_width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let screen_height = unsafe { GetSystemMetrics(SM_CYSCREEN) };

    const RIGHT_MARGIN: i32 = 40;
    const TOP_MARGIN: i32 = 40;

    let x = (screen_width - width - RIGHT_MARGIN).max(0);
    let y = TOP_MARGIN.min((screen_height - height).max(0));

    let extended_style =
        WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_TRANSPARENT;

    let state = Box::new(state);
    let state_pointer = Box::into_raw(state);

    let hwnd = unsafe {
        CreateWindowExW(
            extended_style,
            class_name.as_ptr(),
            null(),
            WS_POPUP,
            x,
            y,
            width,
            height,
            null_mut(),
            null_mut(),
            instance,
            state_pointer.cast(),
        )
    };

    if hwnd.is_null() {
        let state = unsafe { Box::from_raw(state_pointer) };
        if state.font != 0 {
            unsafe {
                DeleteObject(state.font as _);
            }
        }

        unsafe {
            DeleteObject(background_brush as _);
        }

        return Err(format!(
            "failed to create overlay window: {}",
            io::Error::last_os_error()
        ));
    }

    let layered_result = unsafe { SetLayeredWindowAttributes(hwnd, 0, 255, LWA_COLORKEY) };

    if layered_result == 0 {
        unsafe {
            DestroyWindow(hwnd);
        }

        return Err(format!(
            "failed to configure transparent overlay: {}",
            io::Error::last_os_error()
        ));
    }

    unsafe {
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        UpdateWindow(hwnd);
    }

    let timer = unsafe { SetTimer(hwnd, TIMER_ID, timer_interval_ms, None) };
    if timer == 0 {
        unsafe {
            DestroyWindow(hwnd);
        }

        return Err(format!(
            "failed to create overlay timer: {}",
            io::Error::last_os_error()
        ));
    }

    loop {
        let mut message: MSG = unsafe { zeroed() };
        let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };

        if result == -1 {
            return Err(format!(
                "overlay message loop failed: {}",
                io::Error::last_os_error()
            ));
        }

        if result == 0 {
            break;
        }

        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    unsafe {
        DeleteObject(background_brush as _);
    }

    Ok(())
}
