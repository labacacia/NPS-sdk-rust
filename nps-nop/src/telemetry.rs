// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NOP orchestration telemetry. Port of the .NET `NopInstrumentation` /
//! `NopTelemetry`. Instrument names, units and descriptions match the .NET
//! reference exactly.

use std::sync::Arc;

use nps_core::telemetry::{Counter, Histogram, Meter, TraceSource};

/// ActivitySource / Meter name for the NOP layer. Matches
/// `NopInstrumentation.ActivitySourceName` / `.MeterName`.
pub const INSTRUMENTATION_NAME: &str = "nps.nop";

/// Instrumentation version. Matches `NopInstrumentation.Version`.
pub const INSTRUMENTATION_VERSION: &str = "1.0.0";

/// NOP telemetry instruments. Mirrors the static `NopTelemetry` members in .NET.
pub struct NopTelemetry {
    pub meter: Meter,
    pub source: TraceSource,
    /// `nps.nop.task.duration_ms` — NOP task total execution duration.
    pub task_duration_ms: Arc<Histogram>,
    /// `nps.nop.node.duration_ms` — NOP DAG node execution duration.
    pub node_duration_ms: Arc<Histogram>,
    /// `nps.nop.node.retries` — NOP DAG node retry attempts.
    pub node_retries: Arc<Counter>,
    /// `nps.nop.tasks.completed` — NOP tasks completed successfully.
    pub tasks_completed: Arc<Counter>,
    /// `nps.nop.tasks.failed` — NOP tasks that failed or timed out.
    pub tasks_failed: Arc<Counter>,
}

impl Default for NopTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl NopTelemetry {
    pub fn new() -> Self {
        let meter = Meter::new(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
        let task_duration_ms = meter.histogram(
            "nps.nop.task.duration_ms",
            "ms",
            "NOP task total execution duration",
        );
        let node_duration_ms = meter.histogram(
            "nps.nop.node.duration_ms",
            "ms",
            "NOP DAG node execution duration",
        );
        let node_retries = meter.counter(
            "nps.nop.node.retries",
            "{retries}",
            "NOP DAG node retry attempts",
        );
        let tasks_completed = meter.counter(
            "nps.nop.tasks.completed",
            "{tasks}",
            "NOP tasks completed successfully",
        );
        let tasks_failed = meter.counter(
            "nps.nop.tasks.failed",
            "{tasks}",
            "NOP tasks that failed or timed out",
        );
        Self {
            meter,
            source: TraceSource::new(INSTRUMENTATION_NAME),
            task_duration_ms,
            node_duration_ms,
            node_retries,
            tasks_completed,
            tasks_failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nps_core::telemetry::SpanRecorder;

    #[test]
    fn instrument_names_match_dotnet() {
        let t = NopTelemetry::new();
        let names: Vec<&str> = t.meter.snapshot().iter().map(|s| s.name).collect();
        assert!(names.contains(&"nps.nop.task.duration_ms"));
        assert!(names.contains(&"nps.nop.node.duration_ms"));
        assert!(names.contains(&"nps.nop.node.retries"));
        assert!(names.contains(&"nps.nop.tasks.completed"));
        assert!(names.contains(&"nps.nop.tasks.failed"));
    }

    #[test]
    fn instruments_accumulate() {
        let t = NopTelemetry::new();
        t.tasks_completed.inc();
        t.tasks_failed.inc();
        t.node_retries.add(3, &[]);
        t.task_duration_ms.record(100.0);
        t.node_duration_ms.record(25.0);

        assert_eq!(t.tasks_completed.total(), 1);
        assert_eq!(t.tasks_failed.total(), 1);
        assert_eq!(t.node_retries.total(), 3);
        assert_eq!(t.task_duration_ms.sum(), 100.0);
        assert_eq!(t.node_duration_ms.count(), 1);
    }

    #[test]
    fn spans_recorded_via_source() {
        let t = NopTelemetry::new();
        let rec = SpanRecorder::new();
        t.source.set_recorder(rec.clone());
        {
            t.source.start_span("dag.execute");
        }
        assert_eq!(rec.count(), 1);
        assert_eq!(rec.spans()[0].source, "nps.nop");
    }
}
