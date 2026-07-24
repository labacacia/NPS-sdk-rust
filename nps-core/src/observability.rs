// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Framework-agnostic daemon observability utilities.
//!
//! Port of the .NET `NPS.Daemon.Observability` assembly, stripped of its
//! ASP.NET / Kestrel dependencies so the pieces work with any transport
//! (`tiny_http`, custom TCP, tests). Provides:
//!
//! - health/readiness probe rendering ([`HealthProbeRenderer`]) matching the
//!   `/healthz` and `/readyz` JSON shapes,
//! - a Prometheus-text metrics registry ([`MetricsRegistry`]) for `/metrics`,
//! - a JSON structured-log line helper ([`json_log_line`]),
//! - a graceful-shutdown coordinator ([`ShutdownState`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// ── Health / readiness ─────────────────────────────────────────────────────────

/// Transport-neutral health/readiness response. Port of .NET `HealthProbeResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthProbeResponse {
    pub status_code: u16,
    pub content_type: String,
    pub body: String,
    pub status: String,
    pub reason: Option<String>,
}

/// A readiness probe — daemons register one per backing dependency; `/readyz`
/// returns 503 if any fails. Port of .NET `IReadinessProbe`.
pub trait ReadinessProbe {
    /// Short name used in the JSON response (e.g. `"storage"`).
    fn name(&self) -> &str;
    /// Returns `None` on success, `Some(reason)` on failure.
    fn check(&self) -> Option<String>;
}

/// Inline probe wrapping a closure. Port of .NET `DelegateReadinessProbe`.
pub struct DelegateReadinessProbe {
    name: String,
    check: Box<dyn Fn() -> Option<String> + Send + Sync>,
}

impl DelegateReadinessProbe {
    pub fn new(
        name: impl Into<String>,
        check: impl Fn() -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            check: Box::new(check),
        }
    }
}

impl ReadinessProbe for DelegateReadinessProbe {
    fn name(&self) -> &str {
        &self.name
    }
    fn check(&self) -> Option<String> {
        (self.check)()
    }
}

/// Renders liveness and readiness probes without any HTTP framework.
/// Port of .NET `HealthProbeRenderer`.
pub struct HealthProbeRenderer;

impl HealthProbeRenderer {
    pub const JSON_CONTENT_TYPE: &'static str = "application/json; charset=utf-8";

    /// Liveness response used by `/healthz`.
    pub fn render_healthz() -> HealthProbeResponse {
        Self::ok()
    }

    /// Runs the supplied probes and renders the `/readyz` response. With no
    /// probes, readiness is `ok`. Returns the first failing probe's reason.
    pub fn render_readyz<'a>(
        probes: impl IntoIterator<Item = &'a dyn ReadinessProbe>,
    ) -> HealthProbeResponse {
        for probe in probes {
            if let Some(reason) = probe.check() {
                return Self::error(reason);
            }
        }
        Self::ok()
    }

    fn ok() -> HealthProbeResponse {
        HealthProbeResponse {
            status_code: 200,
            content_type: Self::JSON_CONTENT_TYPE.into(),
            body: "{\"status\":\"ok\"}".into(),
            status: "ok".into(),
            reason: None,
        }
    }

    fn error(reason: String) -> HealthProbeResponse {
        let body = format!(
            "{{\"status\":\"error\",\"reason\":{}}}",
            json_string(&reason)
        );
        HealthProbeResponse {
            status_code: 503,
            content_type: Self::JSON_CONTENT_TYPE.into(),
            body,
            status: "error".into(),
            reason: Some(reason),
        }
    }
}

// ── Metrics registry ────────────────────────────────────────────────────────────

/// Prometheus text-exposition content type for `/metrics`. Matches .NET
/// `MetricsEndpoint.ContentType`.
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const CELL_SEPARATOR: char = '\u{1f}';

/// Lightweight Prometheus-compatible counter/gauge registry backing `/metrics`.
/// Port of .NET `MetricsRegistry`.
#[derive(Default)]
pub struct MetricsRegistry {
    entries: Mutex<Vec<MetricEntry>>,
}

enum MetricEntry {
    Counter(PromCounter),
    Gauge(PromGauge),
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a monotonic counter (one cell per label-value tuple).
    pub fn register_counter(
        &self,
        name: &'static str,
        help: &'static str,
        label_names: &[&'static str],
    ) -> PromCounterHandle {
        let cells = std::sync::Arc::new(Mutex::new(HashMap::<String, f64>::new()));
        let labels: Vec<&'static str> = label_names.to_vec();
        if labels.is_empty() {
            cells.lock().unwrap().insert(String::new(), 0.0);
        }
        self.entries.lock().unwrap().push(MetricEntry::Counter(PromCounter {
            name,
            help,
            labels: labels.clone(),
            cells: cells.clone(),
        }));
        PromCounterHandle { labels, cells }
    }

    /// Registers a gauge (may go up and down).
    pub fn register_gauge(&self, name: &'static str, help: &'static str) -> PromGaugeHandle {
        let value = std::sync::Arc::new(Mutex::new(0.0f64));
        self.entries.lock().unwrap().push(MetricEntry::Gauge(PromGauge {
            name,
            help,
            value: value.clone(),
        }));
        PromGaugeHandle { value }
    }

    /// Renders the registry in Prometheus exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for e in self.entries.lock().unwrap().iter() {
            match e {
                MetricEntry::Counter(c) => c.write_to(&mut out),
                MetricEntry::Gauge(g) => g.write_to(&mut out),
            }
        }
        out
    }
}

struct PromCounter {
    name: &'static str,
    help: &'static str,
    labels: Vec<&'static str>,
    cells: std::sync::Arc<Mutex<HashMap<String, f64>>>,
}

impl PromCounter {
    fn write_to(&self, out: &mut String) {
        out.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        out.push_str(&format!("# TYPE {} counter\n", self.name));
        for (key, val) in self.cells.lock().unwrap().iter() {
            out.push_str(self.name);
            if !self.labels.is_empty() {
                out.push('{');
                let parts: Vec<&str> = key.split(CELL_SEPARATOR).collect();
                for (i, label) in self.labels.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let v = parts.get(i).copied().unwrap_or("");
                    out.push_str(&format!("{}=\"{}\"", label, escape_label(v)));
                }
                out.push('}');
            }
            out.push_str(&format!(" {}\n", format_double(*val)));
        }
    }
}

/// Handle used to increment a registered counter.
pub struct PromCounterHandle {
    labels: Vec<&'static str>,
    cells: std::sync::Arc<Mutex<HashMap<String, f64>>>,
}

impl PromCounterHandle {
    pub fn inc(&self) {
        self.inc_by(1.0, &[]);
    }

    pub fn inc_labels(&self, label_values: &[&str]) {
        self.inc_by(1.0, label_values);
    }

    pub fn inc_by(&self, by: f64, label_values: &[&str]) {
        let key = self.cell_key(label_values);
        *self.cells.lock().unwrap().entry(key).or_insert(0.0) += by;
    }

    fn cell_key(&self, label_values: &[&str]) -> String {
        if self.labels.is_empty() {
            return String::new();
        }
        let mut key = String::new();
        for i in 0..self.labels.len() {
            if i > 0 {
                key.push(CELL_SEPARATOR);
            }
            key.push_str(label_values.get(i).copied().unwrap_or(""));
        }
        key
    }
}

struct PromGauge {
    name: &'static str,
    help: &'static str,
    value: std::sync::Arc<Mutex<f64>>,
}

impl PromGauge {
    fn write_to(&self, out: &mut String) {
        out.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        out.push_str(&format!("# TYPE {} gauge\n", self.name));
        out.push_str(&format!(
            "{} {}\n",
            self.name,
            format_double(*self.value.lock().unwrap())
        ));
    }
}

/// Handle used to set/adjust a registered gauge.
pub struct PromGaugeHandle {
    value: std::sync::Arc<Mutex<f64>>,
}

impl PromGaugeHandle {
    pub fn set(&self, v: f64) {
        *self.value.lock().unwrap() = v;
    }
    pub fn inc(&self) {
        *self.value.lock().unwrap() += 1.0;
    }
    pub fn dec(&self) {
        *self.value.lock().unwrap() -= 1.0;
    }
    pub fn add(&self, by: f64) {
        *self.value.lock().unwrap() += by;
    }
    pub fn value(&self) -> f64 {
        *self.value.lock().unwrap()
    }
}

fn format_double(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        let s = format!("{v:.16}");
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        trimmed.to_string()
    }
}

fn escape_label(v: &str) -> String {
    if !v.contains(['\\', '"', '\n']) {
        return v.to_string();
    }
    let mut out = String::with_capacity(v.len() + 8);
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

// ── JSON structured logging ─────────────────────────────────────────────────────

/// Log severity levels (case-insensitive names). Port of the .NET `LogLevel`
/// mapping used by `NpsJsonConsoleFormatter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    None,
}

impl LogLevel {
    /// The short name emitted in the JSON `level` field, matching .NET.
    pub fn name(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
            LogLevel::None => "none",
        }
    }

    /// Parses a level name (case-insensitive), accepting both the short and the
    /// .NET `LogLevel` enum names (`information`/`warning`).
    pub fn parse(raw: &str) -> Option<LogLevel> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" | "information" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            "critical" => Some(LogLevel::Critical),
            "none" => Some(LogLevel::None),
            _ => None,
        }
    }
}

/// Env var that overrides the default minimum log level. Matches .NET
/// `JsonStructuredLogging.LogLevelEnvVar`.
pub const LOG_LEVEL_ENV_VAR: &str = "NPS_LOG_LEVEL";

/// Resolves the configured level from `NPS_LOG_LEVEL`, falling back to
/// `fallback`. Port of .NET `JsonStructuredLogging.ResolveLogLevel`.
pub fn resolve_log_level(fallback: LogLevel) -> LogLevel {
    match std::env::var(LOG_LEVEL_ENV_VAR) {
        Ok(raw) if !raw.trim().is_empty() => LogLevel::parse(&raw).unwrap_or(fallback),
        _ => fallback,
    }
}

/// Builds one single-line JSON log record with the operator-runbook fields:
/// `timestamp`, `level`, `msg`, `logger`, and optionally `trace_id`.
/// Port of `NpsJsonConsoleFormatter.Write`.
pub fn json_log_line(
    timestamp_iso: &str,
    level: LogLevel,
    msg: &str,
    logger: &str,
    trace_id: Option<&str>,
) -> String {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!("\"timestamp\":{}", json_string(timestamp_iso)));
    s.push_str(&format!(",\"level\":{}", json_string(level.name())));
    s.push_str(&format!(",\"msg\":{}", json_string(msg)));
    s.push_str(&format!(",\"logger\":{}", json_string(logger)));
    if let Some(tid) = trace_id {
        if !tid.is_empty() {
            s.push_str(&format!(",\"trace_id\":{}", json_string(tid)));
        }
    }
    s.push('}');
    s
}

// ── Graceful shutdown ────────────────────────────────────────────────────────────

/// Default drain timeout for NPS daemons (NPS-Dev #45), in seconds.
/// Matches .NET `GracefulShutdown.DefaultDrainTimeout` (30s).
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;

/// Liveness flag flipped on SIGTERM; read by health probes so `/healthz` (or
/// `/readyz`) can start failing the moment a drain begins. Port of .NET
/// `ShutdownState`.
#[derive(Default)]
pub struct ShutdownState {
    stopping: AtomicBool,
}

impl ShutdownState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    pub fn mark_stopping(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

// ── JSON string helper ───────────────────────────────────────────────────────────

/// Minimal JSON string encoder (quotes + escapes) — avoids pulling serde into
/// the hot logging path and keeps the module self-contained.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Health ────────────────────────────────────────────────────────────────

    #[test]
    fn render_healthz_returns_ok_json() {
        let r = HealthProbeRenderer::render_healthz();
        assert_eq!(r.status_code, 200);
        assert_eq!(r.content_type, "application/json; charset=utf-8");
        assert_eq!(r.status, "ok");
        assert!(r.body.contains("\"status\":\"ok\""));
    }

    #[test]
    fn render_readyz_no_probes_is_ok() {
        let probes: Vec<&dyn ReadinessProbe> = vec![];
        let r = HealthProbeRenderer::render_readyz(probes);
        assert_eq!(r.status_code, 200);
    }

    #[test]
    fn render_readyz_returns_first_probe_failure() {
        let probe = DelegateReadinessProbe::new("storage", || Some("storage unavailable".into()));
        let probes: Vec<&dyn ReadinessProbe> = vec![&probe];
        let r = HealthProbeRenderer::render_readyz(probes);
        assert_eq!(r.status_code, 503);
        assert_eq!(r.status, "error");
        assert_eq!(r.reason.as_deref(), Some("storage unavailable"));
        assert!(r.body.contains("\"reason\":\"storage unavailable\""));
    }

    #[test]
    fn render_readyz_passes_when_all_ok() {
        let ok1 = DelegateReadinessProbe::new("a", || None);
        let ok2 = DelegateReadinessProbe::new("b", || None);
        let probes: Vec<&dyn ReadinessProbe> = vec![&ok1, &ok2];
        let r = HealthProbeRenderer::render_readyz(probes);
        assert_eq!(r.status_code, 200);
    }

    // ── Metrics ─────────────────────────────────────────────────────────────────

    #[test]
    fn metrics_counter_no_labels_renders() {
        let reg = MetricsRegistry::new();
        let c = reg.register_counter("nps_frames_total", "frames", &[]);
        c.inc();
        c.inc_by(4.0, &[]);
        let out = reg.render();
        assert!(out.contains("# TYPE nps_frames_total counter"));
        assert!(out.contains("nps_frames_total 5"));
    }

    #[test]
    fn metrics_counter_with_labels_renders_cells() {
        let reg = MetricsRegistry::new();
        let c = reg.register_counter("nps_req_total", "requests", &["method"]);
        c.inc_labels(&["GET"]);
        c.inc_labels(&["GET"]);
        c.inc_labels(&["POST"]);
        let out = reg.render();
        assert!(out.contains("nps_req_total{method=\"GET\"} 2"));
        assert!(out.contains("nps_req_total{method=\"POST\"} 1"));
    }

    #[test]
    fn metrics_gauge_renders() {
        let reg = MetricsRegistry::new();
        let g = reg.register_gauge("nps_inflight", "in flight");
        g.set(3.0);
        g.inc();
        g.dec();
        let out = reg.render();
        assert!(out.contains("# TYPE nps_inflight gauge"));
        assert!(out.contains("nps_inflight 3"));
        assert_eq!(g.value(), 3.0);
    }

    #[test]
    fn metrics_content_type_matches_dotnet() {
        assert_eq!(
            METRICS_CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }

    // ── Logging ───────────────────────────────────────────────────────────────

    #[test]
    fn json_log_line_has_runbook_fields() {
        let line = json_log_line(
            "2026-07-09T00:00:00.000Z",
            LogLevel::Info,
            "shutdown complete",
            "nps.daemon",
            Some("abc123"),
        );
        assert!(line.contains("\"timestamp\":\"2026-07-09T00:00:00.000Z\""));
        assert!(line.contains("\"level\":\"info\""));
        assert!(line.contains("\"msg\":\"shutdown complete\""));
        assert!(line.contains("\"logger\":\"nps.daemon\""));
        assert!(line.contains("\"trace_id\":\"abc123\""));
    }

    #[test]
    fn json_log_line_omits_empty_trace_id() {
        let line = json_log_line("t", LogLevel::Warn, "m", "l", None);
        assert!(!line.contains("trace_id"));
        assert!(line.contains("\"level\":\"warn\""));
    }

    #[test]
    fn json_log_line_escapes_message() {
        let line = json_log_line("t", LogLevel::Error, "a\"b\\c\nd", "l", None);
        assert!(line.contains("a\\\"b\\\\c\\nd"));
    }

    #[test]
    fn log_level_names_match_dotnet() {
        assert_eq!(LogLevel::Info.name(), "info");
        assert_eq!(LogLevel::Warn.name(), "warn");
        assert_eq!(LogLevel::Critical.name(), "critical");
    }

    #[test]
    fn log_level_parse_accepts_dotnet_names() {
        assert_eq!(LogLevel::parse("Information"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("WARNING"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("bogus"), None);
    }

    #[test]
    fn resolve_log_level_falls_back_when_unset() {
        std::env::remove_var(LOG_LEVEL_ENV_VAR);
        assert_eq!(resolve_log_level(LogLevel::Info), LogLevel::Info);
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────

    #[test]
    fn shutdown_state_flips_on_mark() {
        let s = ShutdownState::new();
        assert!(!s.is_stopping());
        s.mark_stopping();
        assert!(s.is_stopping());
    }

    #[test]
    fn default_drain_timeout_is_30s() {
        assert_eq!(DEFAULT_DRAIN_TIMEOUT_SECS, 30);
    }
}
