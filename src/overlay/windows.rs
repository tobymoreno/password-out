use std::io;
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM};

use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_VCENTER, DeleteObject,
    DrawTextW, EndPaint, GetDC, GetTextExtentPoint32W, PAINTSTRUCT, ReleaseDC, SelectObject,
    SetBkMode, SetTextColor, TRANSPARENT, UpdateWindow,
};

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    GetSystemMetrics, IDC_ARROW, LWA_COLORKEY, LoadCursorW, MSG, PostQuitMessage, RegisterClassW,
    SM_CXSCREEN, SM_CYSCREEN, SW_SHOWNOACTIVATE, SetLayeredWindowAttributes, SetTimer, ShowWindow,
    TranslateMessage, WM_DESTROY, WM_PAINT, WM_TIMER, WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};

const MAX_FONT_SIZE: i32 = 120;
const MIN_FONT_SIZE: i32 = 16;
const FONT_STEP: i32 = 4;
const HORIZONTAL_PADDING: i32 = 80;
const VERTICAL_PADDING: i32 = 40;
const MIN_WIDTH: i32 = 320;
const SCREEN_MARGIN: i32 = 40;
const TOP_MARGIN: i32 = 40;
const SINGLE_LINE_DURATION_MS: u32 = 1600;
const MULTILINE_DURATION_MS: u32 = 5000;
const TIMER_ID: usize = 1;

static OVERLAY_TEXT: OnceLock<Vec<u16>> = OnceLock::new();
static FONT_HANDLE: AtomicIsize = AtomicIsize::new(0);

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn green_color() -> u32 {
    255 << 8
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_PAINT => {
            let mut paint: PAINTSTRUCT = unsafe { zeroed() };
            let hdc = unsafe { BeginPaint(hwnd, &mut paint) };

            if !hdc.is_null() {
                let font = FONT_HANDLE.load(Ordering::Relaxed);

                if font != 0 {
                    unsafe {
                        SelectObject(hdc, font as _);
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

                if let Some(text) = OVERLAY_TEXT.get() {
                    let character_count = text.len().saturating_sub(1) as i32;

                    unsafe {
                        DrawTextW(
                            hdc,
                            text.as_ptr(),
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
            if wparam == TIMER_ID {
                unsafe {
                    DestroyWindow(hwnd);
                }
            }

            0
        }

        WM_DESTROY => {
            let font = FONT_HANDLE.swap(0, Ordering::Relaxed);

            if font != 0 {
                unsafe {
                    DeleteObject(font as _);
                }
            }

            unsafe {
                PostQuitMessage(0);
            }

            0
        }

        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

pub fn show_overlay(message: &str) {
    if let Err(error) = show_overlay_inner(message) {
        eprintln!("password-out overlay error: {error}");
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

fn show_overlay_inner(message: &str) -> Result<(), String> {
    let text = wide(message);

    OVERLAY_TEXT
        .set(text)
        .map_err(|_| "overlay text was already initialized".to_string())?;

    let font_name = wide("Segoe UI");
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
        return Err(format!(
            "failed to register overlay window class: {}",
            io::Error::last_os_error()
        ));
    }

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

    let mut selected_font = 0_isize;
    let mut selected_line_width = 0;
    let mut selected_line_height = 0;
    let mut selected_line_spacing = 0;
    let mut selected_required_height = 0;
    let mut font_size = MAX_FONT_SIZE;

    loop {
        let candidate_font = create_font(&font_name, font_size)?;
        let (line_width, line_height) = measure_lines(screen_dc as isize, candidate_font, &lines)?;

        // Keep line spacing proportional to the selected font instead of
        // using a fixed number of pixels.
        let line_spacing = (font_size / 10).max(2);

        let text_height = (line_height * line_count) + (line_spacing * (line_count - 1).max(0));
        let required_width = line_width + HORIZONTAL_PADDING;
        let required_height = text_height + VERTICAL_PADDING;

        let width_fits = required_width <= maximum_width;
        let height_fits = required_height <= maximum_height;

        if (width_fits && height_fits) || font_size <= MIN_FONT_SIZE {
            selected_font = candidate_font;
            selected_line_width = line_width;
            selected_line_height = line_height;
            selected_line_spacing = line_spacing;
            selected_required_height = required_height;
            break;
        }

        unsafe {
            DeleteObject(candidate_font as _);
        }

        font_size = (font_size - FONT_STEP).max(MIN_FONT_SIZE);
    }

    unsafe {
        ReleaseDC(null_mut(), screen_dc);
    }

    FONT_HANDLE.store(selected_font, Ordering::Relaxed);

    let width = (selected_line_width + HORIZONTAL_PADDING)
        .max(MIN_WIDTH)
        .min(maximum_width);

    let text_height =
        (selected_line_height * line_count) + (selected_line_spacing * (line_count - 1).max(0));

    // selected_required_height was calculated from the final measured font.
    // Keep the safety clamp for extremely large lists even at the minimum font.
    let height = selected_required_height
        .max(text_height + VERTICAL_PADDING)
        .min(maximum_height);

    let x = (screen_width - width) / 2;
    let y = TOP_MARGIN.min((screen_height - height).max(0));

    let extended_style =
        WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_TRANSPARENT;

    let overlay_text = OVERLAY_TEXT
        .get()
        .ok_or_else(|| "overlay text was not initialized".to_string())?;

    let hwnd = unsafe {
        CreateWindowExW(
            extended_style,
            class_name.as_ptr(),
            overlay_text.as_ptr(),
            WS_POPUP,
            x,
            y,
            width,
            height,
            null_mut(),
            null_mut(),
            instance,
            null_mut(),
        )
    };

    if hwnd.is_null() {
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

    let display_duration = if line_count > 1 {
        MULTILINE_DURATION_MS
    } else {
        SINGLE_LINE_DURATION_MS
    };

    let timer = unsafe { SetTimer(hwnd, TIMER_ID, display_duration, None) };

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

    Ok(())
}
