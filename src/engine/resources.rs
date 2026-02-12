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

/// Visitor that extracts the message field from a tracing event.
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
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
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
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
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let timestamp = format_iso8601_utc(std::time::SystemTime::now());

        let level = event.metadata().level();
        let line = format!("{} {} {}", timestamp, level, visitor.message);

        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() >= self.capacity {
                buf.pop_front();
            }
            buf.push_back(line);
        }
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
    fn log_buffer_ring_evicts_oldest() {
        let buf = new_log_buffer(3);
        {
            let mut b = buf.lock().unwrap();
            b.push_back("line1".into());
            b.push_back("line2".into());
            b.push_back("line3".into());
        }
        // Simulate what the layer does
        {
            let mut b = buf.lock().unwrap();
            if b.len() >= 3 {
                b.pop_front();
            }
            b.push_back("line4".into());
        }
        let b = buf.lock().unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b[0], "line2");
        assert_eq!(b[2], "line4");
    }

    #[test]
    fn list_resources_returns_logs_resource() {
        let result = list_resources_impl();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, LOG_URI);
        assert_eq!(result.resources[0].name, "Server Logs");
    }

    #[test]
    fn read_resource_returns_buffer_contents() {
        let buf = new_log_buffer(10);
        {
            let mut b = buf.lock().unwrap();
            b.push_back("hello".into());
            b.push_back("world".into());
        }
        let result = read_resource_impl(LOG_URI, &buf).unwrap();
        assert_eq!(result.contents.len(), 1);
        match &result.contents[0] {
            ResourceContents::TextResourceContents { text, .. } => {
                assert_eq!(text, "hello\nworld");
            }
            _ => panic!("expected text resource contents"),
        }
    }

    #[test]
    fn read_resource_unknown_uri_returns_none() {
        let buf = new_log_buffer(10);
        assert!(read_resource_impl("cratedex://unknown", &buf).is_none());
    }

    #[test]
    fn format_iso8601_utc_produces_valid_timestamp() {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1749997800);
        assert_eq!(format_iso8601_utc(time), "2025-06-15T14:30:00Z");
    }
}
