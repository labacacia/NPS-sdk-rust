// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Lightweight, dependency-free telemetry abstraction (counters, histograms,
//! spans) with an in-memory reader for tests.
//!
//! The .NET SDK wires `System.Diagnostics.Metrics` (`Meter`, `Counter<long>`,
//! `Histogram<double>`) plus `ActivitySource` spans, and stays a no-op until a
//! listener subscribes. Rust has no equivalent in the offline cargo cache
//! (`tracing` is present but only `tracing` + `tracing-core`, with no
//! subscriber/metrics layer), so this module provides a minimal, self-contained
//! meter + span abstraction that call sites in the protocol crates record
//! against. Hosts read the accumulated values via [`Meter::snapshot`] or attach
//! their own exporter; tests use the in-memory snapshot directly.
//!
//! Instrument **names, units and descriptions match the .NET reference exactly**
//! so exporters see identical metric identities across SDKs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A monotonic counter, addressable by label tuples. Port of `Counter<long>`.
#[derive(Debug, Default)]
pub struct Counter {
    cells: Mutex<HashMap<Vec<String>, u64>>,
}

impl Counter {
    /// Increment the unlabelled cell by 1.
    pub fn inc(&self) {
        self.add(1, &[]);
    }

    /// Increment the unlabelled cell by `by`.
    pub fn add(&self, by: u64, labels: &[&str]) {
        let key: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        let mut cells = self.cells.lock().unwrap();
        *cells.entry(key).or_insert(0) += by;
    }

    /// Increment a labelled cell by 1.
    pub fn inc_labels(&self, labels: &[&str]) {
        self.add(1, labels);
    }

    /// Total across all label cells.
    pub fn total(&self) -> u64 {
        self.cells.lock().unwrap().values().sum()
    }

    /// Value of a specific label cell (empty slice = unlabelled).
    pub fn value(&self, labels: &[&str]) -> u64 {
        let key: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        *self.cells.lock().unwrap().get(&key).unwrap_or(&0)
    }
}

/// A histogram of recorded `f64` observations. Port of `Histogram<double>`.
#[derive(Debug, Default)]
pub struct Histogram {
    inner: Mutex<HistogramInner>,
}

#[derive(Debug, Default)]
struct HistogramInner {
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
}

impl Histogram {
    /// Record one observation.
    pub fn record(&self, value: f64) {
        let mut h = self.inner.lock().unwrap();
        if h.count == 0 {
            h.min = value;
            h.max = value;
        } else {
            if value < h.min {
                h.min = value;
            }
            if value > h.max {
                h.max = value;
            }
        }
        h.count += 1;
        h.sum += value;
    }

    /// Number of observations recorded.
    pub fn count(&self) -> u64 {
        self.inner.lock().unwrap().count
    }

    /// Sum of observations.
    pub fn sum(&self) -> f64 {
        self.inner.lock().unwrap().sum
    }

    /// Mean of observations (0.0 when empty).
    pub fn mean(&self) -> f64 {
        let h = self.inner.lock().unwrap();
        if h.count == 0 {
            0.0
        } else {
            h.sum / h.count as f64
        }
    }

    /// Minimum observation (0.0 when empty).
    pub fn min(&self) -> f64 {
        self.inner.lock().unwrap().min
    }

    /// Maximum observation (0.0 when empty).
    pub fn max(&self) -> f64 {
        self.inner.lock().unwrap().max
    }
}

/// Metadata describing a metric instrument (name, unit, description) — mirrors
/// the arguments passed to `Meter.CreateCounter` / `CreateHistogram` in .NET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentInfo {
    pub name: &'static str,
    pub unit: &'static str,
    pub description: &'static str,
}

/// A registered metric — either a counter or a histogram — with its metadata.
pub enum Instrument {
    Counter(InstrumentInfo, Arc<Counter>),
    Histogram(InstrumentInfo, Arc<Histogram>),
}

/// A named meter that owns a set of instruments. Port of `Meter`.
pub struct Meter {
    name: &'static str,
    version: &'static str,
    instruments: Mutex<Vec<Instrument>>,
}

impl Meter {
    pub fn new(name: &'static str, version: &'static str) -> Self {
        Self {
            name,
            version,
            instruments: Mutex::new(Vec::new()),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn version(&self) -> &'static str {
        self.version
    }

    /// Registers and returns a counter.
    pub fn counter(
        &self,
        name: &'static str,
        unit: &'static str,
        description: &'static str,
    ) -> Arc<Counter> {
        let c = Arc::new(Counter::default());
        self.instruments.lock().unwrap().push(Instrument::Counter(
            InstrumentInfo {
                name,
                unit,
                description,
            },
            c.clone(),
        ));
        c
    }

    /// Registers and returns a histogram.
    pub fn histogram(
        &self,
        name: &'static str,
        unit: &'static str,
        description: &'static str,
    ) -> Arc<Histogram> {
        let h = Arc::new(Histogram::default());
        self.instruments
            .lock()
            .unwrap()
            .push(Instrument::Histogram(
                InstrumentInfo {
                    name,
                    unit,
                    description,
                },
                h.clone(),
            ));
        h
    }

    /// In-memory snapshot of all instruments (name → aggregate value).
    /// Analogue of the .NET test `MeterListener`.
    pub fn snapshot(&self) -> Vec<MetricSnapshot> {
        self.instruments
            .lock()
            .unwrap()
            .iter()
            .map(|inst| match inst {
                Instrument::Counter(info, c) => MetricSnapshot {
                    name: info.name,
                    unit: info.unit,
                    description: info.description,
                    kind: MetricKind::Counter,
                    value: c.total() as f64,
                    count: c.total(),
                },
                Instrument::Histogram(info, h) => MetricSnapshot {
                    name: info.name,
                    unit: info.unit,
                    description: info.description,
                    kind: MetricKind::Histogram,
                    value: h.sum(),
                    count: h.count(),
                },
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Histogram,
}

/// One line of a [`Meter::snapshot`].
#[derive(Debug, Clone)]
pub struct MetricSnapshot {
    pub name: &'static str,
    pub unit: &'static str,
    pub description: &'static str,
    pub kind: MetricKind,
    /// Counter total or histogram sum.
    pub value: f64,
    /// Counter total or histogram observation count.
    pub count: u64,
}

// ── Spans ────────────────────────────────────────────────────────────────────

static SPAN_SEQ: AtomicU64 = AtomicU64::new(1);

/// A trace source that starts spans. Port of `ActivitySource`; no-op unless a
/// [`SpanRecorder`] is attached.
pub struct TraceSource {
    name: &'static str,
    recorder: Mutex<Option<Arc<SpanRecorder>>>,
}

impl TraceSource {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            recorder: Mutex::new(None),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Attach an in-memory recorder (as a test listener would).
    pub fn set_recorder(&self, recorder: Arc<SpanRecorder>) {
        *self.recorder.lock().unwrap() = Some(recorder);
    }

    /// Start a span. Returns a guard that records the completed span on drop.
    pub fn start_span(&self, operation: &str) -> Span {
        let recorder = self.recorder.lock().unwrap().clone();
        Span {
            id: SPAN_SEQ.fetch_add(1, Ordering::Relaxed),
            operation: operation.to_string(),
            source: self.name,
            recorder,
            attributes: Vec::new(),
        }
    }
}

/// An in-flight span. Recording happens on [`Span::end`] or drop.
pub struct Span {
    id: u64,
    operation: String,
    source: &'static str,
    recorder: Option<Arc<SpanRecorder>>,
    attributes: Vec<(String, String)>,
}

impl Span {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Attach a key/value attribute (like `Activity.SetTag`).
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.push((key.into(), value.into()));
    }

    /// Explicitly end the span; also happens on drop.
    pub fn end(self) {}
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(rec) = &self.recorder {
            rec.record(RecordedSpan {
                id: self.id,
                operation: std::mem::take(&mut self.operation),
                source: self.source,
                attributes: std::mem::take(&mut self.attributes),
            });
        }
    }
}

/// A completed span captured by a [`SpanRecorder`].
#[derive(Debug, Clone)]
pub struct RecordedSpan {
    pub id: u64,
    pub operation: String,
    pub source: &'static str,
    pub attributes: Vec<(String, String)>,
}

/// In-memory span sink for tests. Analogue of an OTEL in-memory span exporter.
#[derive(Default)]
pub struct SpanRecorder {
    spans: Mutex<Vec<RecordedSpan>>,
}

impl SpanRecorder {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn record(&self, span: RecordedSpan) {
        self.spans.lock().unwrap().push(span);
    }

    /// All recorded spans, in completion order.
    pub fn spans(&self) -> Vec<RecordedSpan> {
        self.spans.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.spans.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_accumulates_labelled_and_unlabelled() {
        let m = Meter::new("nps.test", "1.0.0");
        let c = m.counter("nps.test.count", "{x}", "test");
        c.inc();
        c.add(4, &[]);
        c.inc_labels(&["a"]);
        c.inc_labels(&["a"]);
        c.inc_labels(&["b"]);
        assert_eq!(c.value(&[]), 5);
        assert_eq!(c.value(&["a"]), 2);
        assert_eq!(c.value(&["b"]), 1);
        assert_eq!(c.total(), 8);
    }

    #[test]
    fn histogram_tracks_count_sum_min_max_mean() {
        let m = Meter::new("nps.test", "1.0.0");
        let h = m.histogram("nps.test.ms", "ms", "test");
        h.record(10.0);
        h.record(20.0);
        h.record(30.0);
        assert_eq!(h.count(), 3);
        assert_eq!(h.sum(), 60.0);
        assert_eq!(h.mean(), 20.0);
        assert_eq!(h.min(), 10.0);
        assert_eq!(h.max(), 30.0);
    }

    #[test]
    fn snapshot_reports_all_instruments_with_metadata() {
        let m = Meter::new("nps.test", "1.0.0");
        let c = m.counter("nps.test.count", "{x}", "count help");
        let h = m.histogram("nps.test.ms", "ms", "hist help");
        c.add(3, &[]);
        h.record(5.0);
        let snap = m.snapshot();
        assert_eq!(snap.len(), 2);
        let counter = snap.iter().find(|s| s.name == "nps.test.count").unwrap();
        assert_eq!(counter.kind, MetricKind::Counter);
        assert_eq!(counter.value, 3.0);
        assert_eq!(counter.description, "count help");
        let hist = snap.iter().find(|s| s.name == "nps.test.ms").unwrap();
        assert_eq!(hist.kind, MetricKind::Histogram);
        assert_eq!(hist.count, 1);
        assert_eq!(hist.unit, "ms");
    }

    #[test]
    fn spans_are_noop_without_recorder() {
        let src = TraceSource::new("nps.test");
        let span = src.start_span("op");
        span.end(); // no panic, nothing recorded
    }

    #[test]
    fn spans_recorded_on_drop_with_attributes() {
        let src = TraceSource::new("nps.test");
        let rec = SpanRecorder::new();
        src.set_recorder(rec.clone());
        {
            let mut s = src.start_span("frame.process");
            s.set_attribute("frame.type", "query");
        }
        {
            src.start_span("frame.process2");
        }
        let spans = rec.spans();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].operation, "frame.process");
        assert_eq!(spans[0].source, "nps.test");
        assert_eq!(spans[0].attributes[0], ("frame.type".into(), "query".into()));
    }
}
