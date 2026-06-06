//! Live progress display for `holocron audit` (#36).
//!
//! Two modes:
//!   * **TTY**: in-place spinner block — one line per auditor, the
//!     active ones rotate through `⠁⠂⠄⠂` etc. while pending. When an
//!     auditor finishes the line is rewritten with a status glyph and
//!     elapsed time.
//!   * **Log**: one line per event with a timestamp prefix. Used for
//!     non-TTY destinations (CI logs, piped output) where ANSI escapes
//!     and carriage-return rewrites would render as garbage.
//!
//! The CLI picks the mode via `--progress {auto,tty,log,off}` (default
//! `auto` — TTY if stderr is a terminal). The display always writes to
//! stderr so it doesn't contaminate stdout if the user pipes the
//! report somewhere.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use holocron_core::{AuditorEvent, RunStatus};
use tokio::sync::mpsc;

/// User-facing choice for the progress display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
#[clap(rename_all = "lowercase")]
pub enum ProgressMode {
    /// Auto-detect: TTY block if stderr is a terminal, log otherwise.
    #[default]
    Auto,
    /// Force TTY mode (spinner block, ANSI cursor moves).
    Tty,
    /// Force log mode (one line per event, no ANSI).
    Log,
    /// Disable progress output entirely.
    Off,
}

/// Resolve `Auto` to the concrete TTY/Log decision based on stderr.
/// Returns `None` for `Off` so callers can skip wiring the sink.
#[must_use]
pub fn resolve_mode(choice: ProgressMode) -> Option<ResolvedMode> {
    match choice {
        ProgressMode::Off => None,
        ProgressMode::Tty => Some(ResolvedMode::Tty),
        ProgressMode::Log => Some(ResolvedMode::Log),
        ProgressMode::Auto => {
            if std::io::stderr().is_terminal() {
                Some(ResolvedMode::Tty)
            } else {
                Some(ResolvedMode::Log)
            }
        }
    }
}

/// The mode actually chosen for this run (Auto already resolved).
#[derive(Debug, Clone, Copy)]
pub enum ResolvedMode {
    Tty,
    Log,
}

/// Spawn a background task that consumes events from the runner and
/// renders them according to `mode`. Returns the `ProgressSink` to pass
/// to `Runner::with_progress(...)` plus a `JoinHandle` the caller
/// should await after the runner finishes (so the display drains).
#[must_use]
pub fn spawn_display(
    mode: ResolvedMode,
    total_auditors: usize,
) -> (holocron_core::ProgressSink, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = match mode {
        ResolvedMode::Tty => tokio::spawn(run_tty_display(rx, total_auditors)),
        ResolvedMode::Log => tokio::spawn(run_log_display(rx)),
    };
    (tx, handle)
}

// ─── log mode ─────────────────────────────────────────────────────────

async fn run_log_display(mut rx: mpsc::UnboundedReceiver<AuditorEvent>) {
    while let Some(ev) = rx.recv().await {
        let ts = chrono::Utc::now().format("%H:%M:%S%.3f");
        match ev {
            AuditorEvent::Started { meta } => {
                eprintln!("[{ts}] start    {} ({})", meta.name, meta.category);
            }
            AuditorEvent::Finished { meta, status, duration } => {
                let secs = duration.as_secs_f64();
                let s = match status {
                    RunStatus::Ok => "ok",
                    RunStatus::Failed => "failed",
                    RunStatus::TimedOut => "timed-out",
                    RunStatus::SkippedMissing => "skipped (not installed)",
                    RunStatus::SkippedDisabled => "skipped (disabled in rc)",
                };
                eprintln!("[{ts}] {s:<10} {} ({secs:.1}s)", meta.name);
            }
        }
    }
}

// ─── TTY mode ─────────────────────────────────────────────────────────

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Clone)]
struct LineState {
    started_at: Option<Instant>,
    finished: Option<(RunStatus, Duration)>,
}

async fn run_tty_display(mut rx: mpsc::UnboundedReceiver<AuditorEvent>, total_auditors: usize) {
    // Map auditor name -> line state. BTreeMap so render order is
    // deterministic (alphabetical) — same as the final report.
    let mut lines: BTreeMap<&'static str, LineState> = BTreeMap::new();
    let mut frame_idx: usize = 0;
    let mut first_render = true;

    let mut tick = tokio::time::interval(Duration::from_millis(80));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Some(AuditorEvent::Started { meta }) => {
                        lines.insert(
                            meta.name,
                            LineState { started_at: Some(Instant::now()), finished: None },
                        );
                    }
                    Some(AuditorEvent::Finished { meta, status, duration }) => {
                        let entry = lines
                            .entry(meta.name)
                            .or_insert(LineState { started_at: None, finished: None });
                        entry.finished = Some((status, duration));
                    }
                    None => {
                        // Channel closed — final render then exit. Use
                        // a frame that's stable; spinner positions will
                        // all be replaced with finished glyphs anyway.
                        render_tty(&lines, &mut first_render, frame_idx, total_auditors);
                        break;
                    }
                }
                render_tty(&lines, &mut first_render, frame_idx, total_auditors);
            }
            _ = tick.tick() => {
                frame_idx = (frame_idx + 1) % SPINNER_FRAMES.len();
                render_tty(&lines, &mut first_render, frame_idx, total_auditors);
            }
        }
    }
    // Final newline so the grade card / outage banner starts on a
    // fresh line.
    let _ = writeln!(std::io::stderr());
}

fn render_tty(
    lines: &BTreeMap<&'static str, LineState>,
    first: &mut bool,
    frame_idx: usize,
    total: usize,
) {
    let mut stderr = std::io::stderr().lock();
    // Move cursor up to the start of the block (if we've already
    // rendered before), then clear each line as we re-render. ANSI:
    //   ESC [ N A   move up N
    //   ESC [ 2 K   erase the entire line
    if !*first {
        let _ = write!(stderr, "\x1b[{}A", lines.len() + 1);
    }
    *first = false;

    let done = lines.values().filter(|l| l.finished.is_some()).count();
    let _ = writeln!(stderr, "\x1b[2KAuditors: {done}/{total} done");
    for (name, state) in lines {
        let _ = write!(stderr, "\x1b[2K");
        if let Some((status, duration)) = state.finished {
            let (glyph, label) = match status {
                RunStatus::Ok => ("\x1b[32m✓\x1b[0m", "ok"),
                RunStatus::Failed => ("\x1b[31m✗\x1b[0m", "failed"),
                RunStatus::TimedOut => ("\x1b[31m⌛\x1b[0m", "timed out"),
                RunStatus::SkippedMissing => ("\x1b[33m⊘\x1b[0m", "not installed"),
                RunStatus::SkippedDisabled => ("\x1b[33m⊘\x1b[0m", "disabled"),
            };
            let secs = duration.as_secs_f64();
            let _ = writeln!(stderr, "  {glyph} {name:<22} {secs:>6.1}s  {label}");
        } else {
            let elapsed = state.started_at.map_or(0.0, |t| t.elapsed().as_secs_f64());
            let frame = SPINNER_FRAMES[frame_idx];
            let _ = writeln!(stderr, "  \x1b[36m{frame}\x1b[0m {name:<22} {elapsed:>6.1}s");
        }
    }
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_off_returns_none() {
        assert!(resolve_mode(ProgressMode::Off).is_none());
    }

    #[test]
    fn explicit_tty_returns_tty_even_when_stderr_is_pipe() {
        // In `cargo test` the stderr is captured (not a TTY), but the
        // explicit choice MUST win regardless of detection.
        assert!(matches!(resolve_mode(ProgressMode::Tty), Some(ResolvedMode::Tty)));
    }

    #[test]
    fn explicit_log_returns_log() {
        assert!(matches!(resolve_mode(ProgressMode::Log), Some(ResolvedMode::Log)));
    }

    #[test]
    fn auto_resolves_to_log_when_stderr_is_not_a_terminal() {
        // Under `cargo test` stderr is captured. We rely on that to
        // assert Auto picks Log. If this ever runs against a real TTY
        // (manual cargo test --no-capture in a terminal) the assertion
        // would flip — that's expected behavior, not a bug.
        assert!(matches!(resolve_mode(ProgressMode::Auto), Some(ResolvedMode::Log)));
    }
}
