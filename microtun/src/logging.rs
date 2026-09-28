use std::io::{self, IsTerminal, Write};

use crossterm::{
    cursor::Show,
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode, is_raw_mode_enabled},
};

/// Install a process-wide panic hook that keeps diagnostics visible.
///
/// The console command runs in raw mode on the terminal's alternate screen. A
/// panic hook runs before unwinding, so without restoring the terminal first the
/// standard Rust panic report can disappear when the TUI cleanup switches back
/// to the main screen.
pub(crate) fn install_panic_hook() {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        restore_terminal_for_panic();

        // Write directly to stderr instead of tracing: a panic can happen before
        // a command has initialized its tracing subscriber. Ignore write errors
        // so a broken stderr cannot turn the original panic into a double panic.
        let _ = writeln!(io::stderr().lock(), "microtun: fatal panic");
        default_hook(panic_info);
    }));
}

fn restore_terminal_for_panic() {
    if !io::stdout().is_terminal() || !is_raw_mode_enabled().unwrap_or(false) {
        return;
    }

    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, Show);
}

/// Install the process-wide tracing subscriber used by host commands.
///
/// `RUST_LOG` always wins. `default_filter` is only used when the environment
/// does not provide a filter, which lets commands choose a sensible baseline
/// without duplicating subscriber setup.
pub(crate) fn init(default_filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .init();
}
