use cocoa::appkit::{
    NSApp, NSApplication, NSApplicationActivationPolicyAccessory,
    NSBackingStoreBuffered, NSColor, NSScreen, NSTextField,
};
use cocoa::base::{id, nil, NO, YES};
use cocoa::foundation::{NSAutoreleasePool, NSPoint, NSRect, NSSize, NSString};
use objc::{class, msg_send, sel, sel_impl};
use std::time::Duration;

const FONT_SIZE: f64 = 44.0;
const HORIZONTAL_PADDING: f64 = 80.0;
const VERTICAL_PADDING: f64 = 30.0;
const MIN_WIDTH: f64 = 320.0;
const SCREEN_MARGIN: f64 = 40.0;
const TOP_MARGIN: f64 = 40.0;
const DISPLAY_DURATION_MS: u64 = 1600;

fn nsstring(value: &str) -> id {
    unsafe { NSString::alloc(nil).init_str(value) }
}

pub fn show_overlay(message: &str) {
    unsafe {
        let _pool = NSAutoreleasePool::new(nil);

        let app = NSApp();
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);

        let screen = NSScreen::mainScreen(nil);
        let screen_frame = if screen != nil {
            screen.visibleFrame()
        } else {
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1440.0, 900.0))
        };

        let color_class = class!(NSColor);
        let clear: id = msg_send![color_class, clearColor];
        let green: id = msg_send![color_class, systemGreenColor];

        let font_class = class!(NSFont);
        let font: id = msg_send![font_class, boldSystemFontOfSize: FONT_SIZE];

        // Build and configure the label first so AppKit can calculate the
        // rendered size of the complete message using the selected font.
        let label = NSTextField::alloc(nil).initWithFrame_(NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(1.0, 1.0),
        ));

        let ns_message = nsstring(message);

        let _: () = msg_send![label, setStringValue: ns_message];
        let _: () = msg_send![label, setAlignment: 2u64];
        let _: () = msg_send![label, setFont: font];
        let _: () = msg_send![label, setTextColor: green];
        let _: () = msg_send![label, setBackgroundColor: clear];
        let _: () = msg_send![label, setBezeled: NO];
        let _: () = msg_send![label, setEditable: NO];
        let _: () = msg_send![label, setSelectable: NO];
        let _: () = msg_send![label, setDrawsBackground: NO];

        let content_size: NSSize = msg_send![label, intrinsicContentSize];

        // Grow to the rendered text width, add padding, and prevent the
        // overlay from extending beyond the visible area of the main screen.
        let max_width = (screen_frame.size.width - (SCREEN_MARGIN * 2.0))
            .max(MIN_WIDTH);

        let width = (content_size.width + HORIZONTAL_PADDING)
            .max(MIN_WIDTH)
            .min(max_width);

        let height = content_size.height + VERTICAL_PADDING;

        let x = screen_frame.origin.x
            + (screen_frame.size.width - width) / 2.0;

        let y = screen_frame.origin.y
            + screen_frame.size.height
            - height
            - TOP_MARGIN;

        let window_rect = NSRect::new(
            NSPoint::new(x, y),
            NSSize::new(width, height),
        );

        let label_rect = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(width, height),
        );
        let _: () = msg_send![label, setFrame: label_rect];

        /*
          Use NSPanel + NSWindowStyleMaskNonactivatingPanel.

          Important:
          - Do NOT call makeKeyAndOrderFront
          - Do NOT call activateIgnoringOtherApps
          - Do NOT use setCanBecomeKeyWindow / setCanBecomeMainWindow
        */

        let panel_class = class!(NSPanel);

        // NSWindowStyleMaskNonactivatingPanel = 1 << 7
        let nonactivating_panel_mask: u64 = 1 << 7;
        let style_mask = nonactivating_panel_mask;

        let panel: id = msg_send![panel_class, alloc];

        let panel: id = msg_send![
            panel,
            initWithContentRect: window_rect
            styleMask: style_mask
            backing: NSBackingStoreBuffered
            defer: NO
        ];

        let _: () = msg_send![panel, setOpaque: NO];
        let _: () = msg_send![panel, setBackgroundColor: clear];
        let _: () = msg_send![panel, setIgnoresMouseEvents: YES];
        let _: () = msg_send![panel, setHidesOnDeactivate: NO];

        // High overlay level.
        let _: () = msg_send![panel, setLevel: 1000i64];

        // Show on all spaces/fullscreen.
        // NSWindowCollectionBehaviorCanJoinAllSpaces = 1 << 0
        // NSWindowCollectionBehaviorFullScreenAuxiliary = 1 << 8
        let collection_behavior: u64 = (1 << 0) | (1 << 8);
        let _: () = msg_send![panel, setCollectionBehavior: collection_behavior];

        let _: () = msg_send![panel, setContentView: label];
        let _: () = msg_send![panel, setAlphaValue: 1.0f64];

        // Non-activating display. Should not steal focus.
        let _: () = msg_send![panel, orderFrontRegardless];

        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(DISPLAY_DURATION_MS));
            std::process::exit(0);
        });

        app.run();
    }
}
