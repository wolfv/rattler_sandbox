//! No-op stand-in for `codex_otel`.
//!
//! The codex Windows port wires telemetry through `codex-otel`. We don't ship
//! that, so the same types and method signatures are reproduced here as
//! no-ops. Once telemetry is needed, replace this module with a real impl.

#![cfg(target_os = "windows")]
#![allow(dead_code)] // stub: fields/methods exist to match the codex API surface.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsigMetricsSettings {
    #[serde(default)]
    pub environment: String,
}

#[derive(Debug, Clone, Default)]
pub enum OtelExporter {
    #[default]
    None,
    Statsig,
}

pub struct OtelSettings {
    pub environment: String,
    pub service_name: String,
    pub service_version: String,
    pub codex_home: PathBuf,
    pub exporter: OtelExporter,
    pub trace_exporter: OtelExporter,
    pub metrics_exporter: OtelExporter,
    pub runtime_metrics: bool,
    pub tracestate: Option<String>,
    pub span_attributes: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct OtelProvider;

impl OtelProvider {
    pub fn from(_: &OtelSettings) -> anyhow::Result<Option<OtelProvider>> {
        Ok(None)
    }

    pub fn shutdown(&self) {}

    pub fn metrics(&self) -> &OtelMetrics {
        static METRICS: OtelMetrics = OtelMetrics;
        &METRICS
    }
}

/// No-op metrics handle.
#[derive(Debug)]
pub struct OtelMetrics;

impl OtelMetrics {
    pub fn counter<A>(&self, _name: &str, _value: u64, _attrs: &A) -> anyhow::Result<()> {
        Ok(())
    }
    pub fn histogram<A>(&self, _name: &str, _value: f64, _attrs: &A) -> anyhow::Result<()> {
        Ok(())
    }
}
