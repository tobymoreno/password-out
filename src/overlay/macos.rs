#![allow(unexpected_cfgs)]
#![allow(unsafe_op_in_unsafe_fn)]

use cocoa::appkit::{
    NSApp, NSApplication, NSApplicationActivationPolicyAccessory, NSBackingStoreBuffered, NSScreen,
    NSTextField,
};
use cocoa::base::{NO, YES, id, nil};
use cocoa::foundation::{NSAutoreleasePool, NSPoint, NSRect, NSSize, NSString};
use objc::{class, msg_send, sel, sel_impl};
use std::ffi::c_void;
use std::time::Duration;

const SINGLE_LINE_FONT_SIZE: f64 = 44.0;
const MULTILINE_FONT_SIZE: f64 = 44.0;
const MULTILINE_LINE_HEIGHT: f64 = 44.0;
const COUNTDOWN_FONT_SIZE: f64 = 28.0;

const SINGLE_HORIZONTAL_PADDING: f64 = 80.0;
const SINGLE_VERTICAL_PADDING: f64 = 30.0;

const MULTILINE_HORIZONTAL_PADDING: f64 = 56.0;
const MULTILINE_VERTICAL_PADDING: f64 = 40.0;
const MULTILINE_CHARACTER_WIDTH_FACTOR: f64 = 0.62;

const COUNTDOWN_WIDTH: f64 = 390.0;
const COUNTDOWN_HEIGHT: f64 = 72.0;

const MIN_WIDTH: f64 = 320.0;
const MAX_MULTILINE_WIDTH: f64 = 1100.0;
const SCREEN_MARGIN: f64 = 40.0;
const TOP_MARGIN: f64 = 40.0;
const RIGHT_MARGIN: f64 = 40.0;
const LEFT_MARGIN: f64 = 28.0;
const BOTTOM_MARGIN: f64 = 28.0;

const DISPLAY_DURATION: Duration = Duration::from_millis(1_600);
const COUNTDOWN_TICK: Duration = Duration::from_secs(1);

const FALLBACK_SCREEN_WIDTH: f64 = 1_440.0;
const FALLBACK_SCREEN_HEIGHT: f64 = 900.0;

const NONACTIVATING_PANEL_STYLE_MASK: u64 = 1 << 7;

const CAN_JOIN_ALL_SPACES: u64 = 1 << 0;
const FULL_SCREEN_AUXILIARY: u64 = 1 << 8;
const PANEL_COLLECTION_BEHAVIOR: u64 = CAN_JOIN_ALL_SPACES | FULL_SCREEN_AUXILIARY;

const OVERLAY_WINDOW_LEVEL: i64 = 1_000;

const ALIGN_LEFT: u64 = 0;
const ALIGN_CENTER: u64 = 2;

type DispatchQueue = *mut c_void;

unsafe extern "C" {
    static mut _dispatch_main_q: c_void;

    fn dispatch_async_f(
        queue: DispatchQueue,
        context: *mut c_void,
        work: unsafe extern "C" fn(*mut c_void),
    );
}

struct CountdownUpdate {
    text_view: usize,
    text: String,
}

fn nsstring(value: &str) -> id {
    unsafe { NSString::alloc(nil).init_str(value) }
}

fn fallback_screen_frame() -> NSRect {
    NSRect::new(
        NSPoint::new(0.0, 0.0),
        NSSize::new(FALLBACK_SCREEN_WIDTH, FALLBACK_SCREEN_HEIGHT),
    )
}

unsafe fn main_screen_frame() -> NSRect {
    let screen = NSScreen::mainScreen(nil);

    if screen == nil {
        fallback_screen_frame()
    } else {
        screen.visibleFrame()
    }
}

unsafe fn appkit_colors() -> (id, id) {
    let color_class = class!(NSColor);

    let clear: id = msg_send![color_class, clearColor];
    let green: id = msg_send![color_class, systemGreenColor];

    (clear, green)
}

unsafe fn single_line_font() -> id {
    let font_class = class!(NSFont);

    msg_send![font_class, boldSystemFontOfSize: SINGLE_LINE_FONT_SIZE]
}

unsafe fn multiline_font() -> id {
    let font_class = class!(NSFont);
    let font: id = msg_send![font_class, userFixedPitchFontOfSize: MULTILINE_FONT_SIZE];

    if font == nil {
        msg_send![font_class, systemFontOfSize: MULTILINE_FONT_SIZE]
    } else {
        font
    }
}

unsafe fn countdown_font() -> id {
    let font_class = class!(NSFont);
    let font: id = msg_send![font_class, userFixedPitchFontOfSize: COUNTDOWN_FONT_SIZE];

    if font == nil {
        msg_send![font_class, boldSystemFontOfSize: COUNTDOWN_FONT_SIZE]
    } else {
        font
    }
}

unsafe fn create_single_line_label(message: &str, font: id, text_color: id, clear_color: id) -> id {
    let initial_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1.0, 1.0));

    let label = NSTextField::alloc(nil).initWithFrame_(initial_frame);
    let ns_message = nsstring(message);

    let _: () = msg_send![label, setStringValue: ns_message];
    let _: () = msg_send![label, setAlignment: ALIGN_CENTER];
    let _: () = msg_send![label, setFont: font];
    let _: () = msg_send![label, setTextColor: text_color];
    let _: () = msg_send![label, setBackgroundColor: clear_color];
    let _: () = msg_send![label, setBezeled: NO];
    let _: () = msg_send![label, setEditable: NO];
    let _: () = msg_send![label, setSelectable: NO];
    let _: () = msg_send![label, setDrawsBackground: NO];

    label
}

unsafe fn create_multiline_text_view(
    message: &str,
    font: id,
    text_color: id,
    clear_color: id,
    alignment: u64,
) -> id {
    let initial_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1.0, 1.0));
    let text_view_class = class!(NSTextView);
    let text_view: id = msg_send![text_view_class, alloc];
    let text_view: id = msg_send![text_view, initWithFrame: initial_frame];
    let ns_message = nsstring(message);

    let _: () = msg_send![text_view, setString: ns_message];
    let _: () = msg_send![text_view, setAlignment: alignment];
    let _: () = msg_send![text_view, setFont: font];
    let _: () = msg_send![text_view, setTextColor: text_color];
    let _: () = msg_send![text_view, setBackgroundColor: clear_color];
    let _: () = msg_send![text_view, setDrawsBackground: NO];
    let _: () = msg_send![text_view, setEditable: NO];
    let _: () = msg_send![text_view, setSelectable: NO];
    let _: () = msg_send![text_view, setRichText: NO];
    let _: () = msg_send![text_view, setImportsGraphics: NO];
    let _: () = msg_send![text_view, setHorizontallyResizable: NO];
    let _: () = msg_send![text_view, setVerticallyResizable: YES];

    let text_container: id = msg_send![text_view, textContainer];
    if text_container != nil {
        let _: () = msg_send![text_container, setWidthTracksTextView: YES];
        let _: () = msg_send![text_container, setContainerSize: NSSize::new(f64::MAX, f64::MAX)];
        let _: () = msg_send![text_container, setLineFragmentPadding: 0.0f64];
    }

    text_view
}

fn multiline_metrics(message: &str) -> (usize, usize) {
    let mut line_count = 0usize;
    let mut longest_line = 0usize;

    for line in message.lines() {
        line_count += 1;
        longest_line = longest_line.max(line.chars().count());
    }

    (line_count.max(1), longest_line.max(1))
}

unsafe fn calculate_single_line_frame(label: id, screen_frame: NSRect) -> NSRect {
    let content_size: NSSize = msg_send![label, intrinsicContentSize];
    let max_width = (screen_frame.size.width - (SCREEN_MARGIN * 2.0)).max(MIN_WIDTH);

    let width = (content_size.width + SINGLE_HORIZONTAL_PADDING)
        .max(MIN_WIDTH)
        .min(max_width);

    let height = content_size.height + SINGLE_VERTICAL_PADDING;

    positioned_center_frame(screen_frame, width, height)
}

fn calculate_multiline_frame(message: &str, screen_frame: NSRect) -> NSRect {
    let (line_count, longest_line) = multiline_metrics(message);

    let estimated_text_width =
        longest_line as f64 * MULTILINE_FONT_SIZE * MULTILINE_CHARACTER_WIDTH_FACTOR;

    let screen_max_width = (screen_frame.size.width - (SCREEN_MARGIN * 2.0)).max(MIN_WIDTH);
    let max_width = screen_max_width.min(MAX_MULTILINE_WIDTH);

    let width = (estimated_text_width + MULTILINE_HORIZONTAL_PADDING)
        .max(MIN_WIDTH)
        .min(max_width);

    let max_height = (screen_frame.size.height - (TOP_MARGIN + SCREEN_MARGIN)).max(120.0);
    let height = ((line_count as f64 * MULTILINE_LINE_HEIGHT) + MULTILINE_VERTICAL_PADDING)
        .max(100.0)
        .min(max_height);

    positioned_center_frame(screen_frame, width, height)
}

fn positioned_center_frame(screen_frame: NSRect, width: f64, height: f64) -> NSRect {
    let x = screen_frame.origin.x + ((screen_frame.size.width - width) / 2.0);
    let y = screen_frame.origin.y + screen_frame.size.height - height - TOP_MARGIN;

    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

fn positioned_bottom_left_frame(screen_frame: NSRect, width: f64, height: f64) -> NSRect {
    let x = screen_frame.origin.x + LEFT_MARGIN;
    let y = screen_frame.origin.y + BOTTOM_MARGIN;

    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

unsafe fn resize_label(label: id, window_frame: NSRect, is_multiline: bool) {
    let horizontal_inset = if is_multiline {
        MULTILINE_HORIZONTAL_PADDING / 2.0
    } else {
        0.0
    };

    let vertical_inset = if is_multiline {
        MULTILINE_VERTICAL_PADDING / 2.0
    } else {
        0.0
    };

    let label_frame = NSRect::new(
        NSPoint::new(horizontal_inset, vertical_inset),
        NSSize::new(
            (window_frame.size.width - (horizontal_inset * 2.0)).max(1.0),
            (window_frame.size.height - (vertical_inset * 2.0)).max(1.0),
        ),
    );

    let _: () = msg_send![label, setFrame: label_frame];
}

unsafe fn resize_countdown_view(text_view: id, window_frame: NSRect) {
    let horizontal_inset = 12.0;
    let vertical_inset = 12.0;

    let frame = NSRect::new(
        NSPoint::new(horizontal_inset, vertical_inset),
        NSSize::new(
            window_frame.size.width - (horizontal_inset * 2.0),
            window_frame.size.height - (vertical_inset * 2.0),
        ),
    );

    let _: () = msg_send![text_view, setFrame: frame];
}

unsafe fn create_panel(window_frame: NSRect, label: id, clear_color: id) -> id {
    let panel_class = class!(NSPanel);
    let panel: id = msg_send![panel_class, alloc];

    let panel: id = msg_send![
        panel,
        initWithContentRect: window_frame
        styleMask: NONACTIVATING_PANEL_STYLE_MASK
        backing: NSBackingStoreBuffered
        defer: NO
    ];

    let _: () = msg_send![panel, setOpaque: NO];
    let _: () = msg_send![panel, setBackgroundColor: clear_color];
    let _: () = msg_send![panel, setIgnoresMouseEvents: YES];
    let _: () = msg_send![panel, setHidesOnDeactivate: NO];

    let _: () = msg_send![panel, setLevel: OVERLAY_WINDOW_LEVEL];
    let _: () = msg_send![panel, setCollectionBehavior: PANEL_COLLECTION_BEHAVIOR];

    let content_view: id = msg_send![panel, contentView];
    let _: () = msg_send![content_view, addSubview: label];
    let _: () = msg_send![panel, setAlphaValue: 1.0f64];

    panel
}

fn should_auto_exit() -> bool {
    std::env::var_os("PASSWORD_OUT_OVERLAY_PERSISTENT").is_none()
}

fn schedule_exit() {
    std::thread::spawn(|| {
        std::thread::sleep(DISPLAY_DURATION);
        std::process::exit(0);
    });
}

fn countdown_message(remaining_seconds: u64) -> String {
    format!("Password Timeout: {remaining_seconds}s")
}

unsafe extern "C" fn apply_countdown_update(context: *mut c_void) {
    if context.is_null() {
        return;
    }

    let update = unsafe { Box::from_raw(context.cast::<CountdownUpdate>()) };
    let text_view = update.text_view as id;
    let ns_message = nsstring(&update.text);

    let _: () = unsafe { msg_send![text_view, setString: ns_message] };
    let _: () = unsafe { msg_send![text_view, setNeedsDisplay: YES] };
}

fn queue_countdown_update(text_view: usize, text: String) {
    let update = Box::new(CountdownUpdate { text_view, text });
    let context = Box::into_raw(update).cast::<c_void>();

    let main_queue = std::ptr::addr_of_mut!(_dispatch_main_q).cast::<c_void>();

    unsafe {
        dispatch_async_f(main_queue, context, apply_countdown_update);
    }
}

fn schedule_countdown(text_view: id, total_seconds: u64) {
    let text_view = text_view as usize;

    std::thread::spawn(move || {
        for remaining in (1..total_seconds).rev() {
            std::thread::sleep(COUNTDOWN_TICK);
            queue_countdown_update(text_view, countdown_message(remaining));
        }

        std::thread::sleep(COUNTDOWN_TICK);
        std::process::exit(0);
    });
}

pub fn show_overlay(message: &str) {
    unsafe {
        let _pool = NSAutoreleasePool::new(nil);

        let app = NSApp();
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);

        let is_multiline = message.contains('\n');
        let screen_frame = main_screen_frame();
        let (clear_color, text_color) = appkit_colors();
        let content_view = if is_multiline {
            create_multiline_text_view(
                message,
                multiline_font(),
                text_color,
                clear_color,
                ALIGN_LEFT,
            )
        } else {
            create_single_line_label(message, single_line_font(), text_color, clear_color)
        };

        let window_frame = if is_multiline {
            calculate_multiline_frame(message, screen_frame)
        } else {
            calculate_single_line_frame(content_view, screen_frame)
        };

        resize_label(content_view, window_frame, is_multiline);

        let panel = create_panel(window_frame, content_view, clear_color);
        let _: () = msg_send![panel, orderFrontRegardless];

        if should_auto_exit() {
            schedule_exit();
        }

        app.run();
    }
}

pub fn show_countdown(total_seconds: u64) {
    if total_seconds == 0 {
        return;
    }

    unsafe {
        let _pool = NSAutoreleasePool::new(nil);

        let app = NSApp();
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);

        let screen_frame = main_screen_frame();
        let (clear_color, text_color) = appkit_colors();
        let initial_message = countdown_message(total_seconds);

        let text_view = create_multiline_text_view(
            &initial_message,
            countdown_font(),
            text_color,
            clear_color,
            ALIGN_LEFT,
        );

        let window_frame =
            positioned_bottom_left_frame(screen_frame, COUNTDOWN_WIDTH, COUNTDOWN_HEIGHT);

        resize_countdown_view(text_view, window_frame);

        let panel = create_panel(window_frame, text_view, clear_color);
        let _: () = msg_send![panel, orderFrontRegardless];

        schedule_countdown(text_view, total_seconds);

        app.run();
    }
}
