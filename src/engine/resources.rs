//! MCP Resources: exposes server logs as a readable resource.

use rmcp::model::{
    Annotated, ListResourcesResult, RawResource, ReadResourceResult, Resource, ResourceContents,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Thread-safe ring buffer of log lines.
pub type LogBuffer = Arc<Mutex<VecDeque<String>>>;

/// Create a new log buffer with the given capacity.
pub fn new_log_buffer(capacity: usize) -> LogBuffer {
    Arc::new(Mutex::new(VecDeque::with_capacity(capacity)))
}

const LOG_URI: &str = "cratedex://logs";

/// Default capacity for log buffers.
pub const LOG_BUFFER_CAPACITY: usize = 500;
const MAX_LOG_LINE_LEN: usize = 500;

// ───── Tracing Layer ─────

/// A tracing subscriber layer that captures log events into a ring buffer.
pub struct LogCaptureLayer {
    buffer: LogBuffer,
    capacity: usize,
}

impl LogCaptureLayer {
    pub fn new(buffer: LogBuffer, capacity: usize) -> Self {
        Self { buffer, capacity }
    }
}

/// Visitor that extracts the message and all structured fields from a tracing event.
struct EventVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            self.fields
                .push((field.name().to_string(), format!("{:?}", value)));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// Format a `SystemTime` as an ISO 8601 / RFC 3339 UTC timestamp.
///
/// Uses Howard Hinnant's civil_from_days algorithm to convert epoch
/// seconds into a calendar date without any external dependencies.
fn format_iso8601_utc(time: std::time::SystemTime) -> String {
    let d = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();

    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // civil_from_days: convert days since Unix epoch to (year, month, day).
    // Reference: https://howardhinnant.github.io/date_algorithms.html
    let days = (secs / 86400) as i64;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, s
    )
}

impl<S: Subscriber> Layer<S> for LogCaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = EventVisitor {
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut visitor);

        let timestamp = format_iso8601_utc(std::time::SystemTime::now());
        let level = event.metadata().level();

        let line = if visitor.fields.is_empty() {
            format!("{timestamp} {level} {}", visitor.message)
        } else {
            use std::fmt::Write;
            let mut buf = format!("{timestamp} {level} {}", visitor.message);
            for (key, val) in &visitor.fields {
                write!(buf, " {key}={val}").unwrap();
            }
            buf
        };
        let line = truncate_log_line(line);

        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() >= self.capacity {
                buf.pop_front();
            }
            buf.push_back(line);
        }
    }
}

fn truncate_log_line(line: String) -> String {
    if line.len() > MAX_LOG_LINE_LEN {
        let suffix = "... (truncated)";
        let mut keep = MAX_LOG_LINE_LEN.saturating_sub(suffix.len());
        // Avoid panicking on multi-byte UTF-8 boundaries.
        while keep > 0 && !line.is_char_boundary(keep) {
            keep -= 1;
        }
        format!("{}{}", &line[..keep], suffix)
    } else {
        line
    }
}

// ───── Resource implementations ─────

pub fn list_resources_impl() -> ListResourcesResult {
    let resource: Resource = Annotated::new(
        RawResource {
            uri: LOG_URI.to_string(),
            name: "Server Logs".to_string(),
            title: Some("Cratedex Server Logs".to_string()),
            description: Some(
                "Recent log entries from the cratedex server. Returns the last 500 log lines."
                    .to_string(),
            ),
            mime_type: Some("text/plain".to_string()),
            size: None,
            icons: None,
            meta: None,
        },
        None,
    );
    ListResourcesResult {
        meta: None,
        resources: vec![resource],
        next_cursor: None,
    }
}

pub fn read_resource_impl(uri: &str, buffer: &LogBuffer) -> Option<ReadResourceResult> {
    if uri != LOG_URI {
        return None;
    }

    let text = match buffer.lock() {
        Ok(buf) => buf.iter().cloned().collect::<Vec<_>>().join("\n"),
        Err(_) => "Error: could not read log buffer".to_string(),
    };

    Some(ReadResourceResult {
        contents: vec![ResourceContents::TextResourceContents {
            uri: LOG_URI.to_string(),
            mime_type: Some("text/plain".to_string()),
            text,
            meta: None,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_iso8601_utc_produces_valid_timestamp() {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_749_997_800);
        assert_eq!(format_iso8601_utc(time), "2025-06-15T14:30:00Z");
    }

    #[test]
    fn truncate_log_line_caps_output() {
        let line = "x".repeat(600);
        let truncated = truncate_log_line(line);
        assert_eq!(truncated.len(), MAX_LOG_LINE_LEN);
        assert!(truncated.ends_with("... (truncated)"));
    }

    #[test]
    fn truncate_log_line_handles_multibyte_utf8() {
        // Each emoji is 4 bytes. Build a string that forces the cut to land mid-character.
        let emoji = "\u{1F980}"; // crab emoji, 4 bytes
        let line = emoji.repeat(200); // 800 bytes
        let truncated = truncate_log_line(line);
        assert!(truncated.len() <= MAX_LOG_LINE_LEN);
        assert!(truncated.ends_with("... (truncated)"));
        // Must be valid UTF-8 (this would panic if not)
        let _ = truncated.chars().count();
    }

    #[test]
    fn event_visitor_captures_structured_fields() {
        use tracing_subscriber::layer::SubscriberExt;

        let buf = new_log_buffer(10);
        let layer = LogCaptureLayer::new(buf.clone(), 10);

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(id = 42, error = "search failed", "response error");
        });

        let guard = buf.lock().unwrap();
        assert_eq!(guard.len(), 1);
        let line = &guard[0];
        assert!(line.contains("WARN"), "missing level: {line}");
        assert!(line.contains("response error"), "missing message: {line}");
        assert!(line.contains("id=42"), "missing id field: {line}");
        assert!(
            line.contains("search failed"),
            "missing error field: {line}"
        );
    }
}
