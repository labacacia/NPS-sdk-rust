// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP frame-processing telemetry. Port of the .NET `NwpInstrumentation` /
//! `NwpTelemetry`. Instrument names, units and descriptions match the .NET
//! reference exactly so exporters observe identical metric identities.

use std::sync::Arc;

use nps_core::telemetry::{Counter, Histogram, Meter, TraceSource};

/// ActivitySource / Meter name for the NWP layer. Matches
/// `NwpInstrumentation.ActivitySourceName` / `.MeterName`.
pub const INSTRUMENTATION_NAME: &str = "nps.nwp";

/// Instrumentation version. Matches `NwpInstrumentation.Version`.
pub const INSTRUMENTATION_VERSION: &str = "1.0.0";

/// NWP telemetry instruments. Constructed once per process (or per test).
/// Mirrors the static `NwpTelemetry` members in .NET.
pub struct NwpTelemetry {
    pub meter: Meter,
    pub source: TraceSource,
    /// `nps.frames.processed` — total NWP frames processed.
    pub frames_processed: Arc<Counter>,
    /// `nps.frames.processing_ms` — NWP frame processing duration.
    pub frame_duration_ms: Arc<Histogram>,
    /// `nps.cgn.consumed` — CGN units consumed in NWP responses.
    pub cgn_consumed: Arc<Counter>,
    /// `nps.frames.errors` — NWP frames that returned an error response.
    pub frame_errors: Arc<Counter>,
}

impl Default for NwpTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl NwpTelemetry {
    pub fn new() -> Self {
        let meter = Meter::new(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
        let frames_processed = meter.counter(
            "nps.frames.processed",
            "{frames}",
            "Total NWP frames processed",
        );
        let frame_duration_ms = meter.histogram(
            "nps.frames.processing_ms",
            "ms",
            "NWP frame processing duration",
        );
        let cgn_consumed = meter.counter(
            "nps.cgn.consumed",
            "{cgn}",
            "CGN units consumed in NWP responses",
        );
        let frame_errors = meter.counter(
            "nps.frames.errors",
            "{frames}",
            "NWP frames that returned an error response",
        );
        Self {
            meter,
            source: TraceSource::new(INSTRUMENTATION_NAME),
            frames_processed,
            frame_duration_ms,
            cgn_consumed,
            frame_errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nps_core::telemetry::SpanRecorder;

    #[test]
    fn instrument_names_match_dotnet() {
        let t = NwpTelemetry::new();
        let names: Vec<&str> = t.meter.snapshot().iter().map(|s| s.name).collect();
        assert!(names.contains(&"nps.frames.processed"));
        assert!(names.contains(&"nps.frames.processing_ms"));
        assert!(names.contains(&"nps.cgn.consumed"));
        assert!(names.contains(&"nps.frames.errors"));
    }

    #[test]
    fn counters_and_histogram_accumulate() {
        let t = NwpTelemetry::new();
        t.frames_processed.inc();
        t.frames_processed.inc();
        t.frame_errors.inc();
        t.cgn_consumed.add(120, &[]);
        t.frame_duration_ms.record(4.5);
        t.frame_duration_ms.record(9.5);

        assert_eq!(t.frames_processed.total(), 2);
        assert_eq!(t.frame_errors.total(), 1);
        assert_eq!(t.cgn_consumed.total(), 120);
        assert_eq!(t.frame_duration_ms.count(), 2);
        assert_eq!(t.frame_duration_ms.mean(), 7.0);
    }

    #[test]
    fn spans_recorded_via_source() {
        let t = NwpTelemetry::new();
        let rec = SpanRecorder::new();
        t.source.set_recorder(rec.clone());
        {
            let mut s = t.source.start_span("query.execute");
            s.set_attribute("node", "products");
        }
        assert_eq!(rec.count(), 1);
        assert_eq!(rec.spans()[0].operation, "query.execute");
        assert_eq!(rec.spans()[0].source, "nps.nwp");
    }

    #[test]
    fn meter_identity_matches() {
        let t = NwpTelemetry::new();
        assert_eq!(t.meter.name(), "nps.nwp");
        assert_eq!(t.meter.version(), "1.0.0");
    }
}
