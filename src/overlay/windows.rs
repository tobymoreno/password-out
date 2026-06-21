use std::io;
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM};

use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER,
    DeleteObject, DrawTextW, EndPaint, GetDC, GetTextExtentPoint32W, PAINTSTRUCT, ReleaseDC,
    SelectObject, SetBkMode, SetTextColor, TRANSPARENT, UpdateWindow,
};

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    GetSystemMetrics, IDC_ARROW, LWA_COLORKEY, LoadCursorW, MSG, PostQuitMessage, RegisterClassW,
    SM_CXSCREEN, SM_CYSCREEN, SW_SHOWNOACTIVATE, SetLayeredWindowAttributes, SetTimer, ShowWindow,
    TranslateMessage, WM_DESTROY, WM_PAINT, WM_TIMER, WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};

const FONT_SIZE: i32 = 120;
const HORIZONTAL_PADDING: i32 = 80;
const VERTICAL_PADDING: i32 = 30;
const MIN_WIDTH: i32 = 320;
const SCREEN_MARGIN: i32 = 40;
const TOP_MARGIN: i32 = 40;
const DISPLAY_DURATION_MS: u32 = 1600;
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
                            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
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

fn show_overlay_inner(message: &str) -> Result<(), String> {
    let text = wide(message);

    OVERLAY_TEXT
        .set(text)
        .map_err(|_| "overlay text was already initialized".to_string())?;

    let font_name = wide("Segoe UI");
    let class_name = wide("PasswordOutOverlayWindow");

    let font = unsafe {
        CreateFontW(
            -FONT_SIZE,
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

    FONT_HANDLE.store(font as isize, Ordering::Relaxed);

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

    let screen_dc = unsafe { GetDC(null_mut()) };

    if screen_dc.is_null() {
        return Err(format!(
            "failed to get screen device context: {}",
            io::Error::last_os_error()
        ));
    }

    let previous_font = unsafe { SelectObject(screen_dc, font) };

    let mut text_size: SIZE = unsafe { zeroed() };
    let overlay_text = OVERLAY_TEXT
        .get()
        .ok_or_else(|| "overlay text was not initialized".to_string())?;

    let character_count = overlay_text.len().saturating_sub(1) as i32;

    let measured = unsafe {
        GetTextExtentPoint32W(
            screen_dc,
            overlay_text.as_ptr(),
            character_count,
            &mut text_size,
        )
    };

    if !previous_font.is_null() {
        unsafe {
            SelectObject(screen_dc, previous_font);
        }
    }

    unsafe {
        ReleaseDC(null_mut(), screen_dc);
    }

    if measured == 0 {
        return Err(format!(
            "failed to measure overlay text: {}",
            io::Error::last_os_error()
        ));
    }

    let maximum_width = (screen_width - (SCREEN_MARGIN * 2)).max(MIN_WIDTH);

    let width = (text_size.cx + HORIZONTAL_PADDING)
        .max(MIN_WIDTH)
        .min(maximum_width);

    let height = text_size.cy + VERTICAL_PADDING;

    let x = (screen_width - width) / 2;
    let y = TOP_MARGIN.min((screen_height - height).max(0));

    let extended_style =
        WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_TRANSPARENT;

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

    let timer = unsafe { SetTimer(hwnd, TIMER_ID, DISPLAY_DURATION_MS, None) };

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
