// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::error::{NpsError, NpsResult};
use crate::frames::TaskFrame;
use crate::models::NopTaskStatus;

pub struct NopClient {
    base_url: String,
    http:     reqwest::Client,
}

impl NopClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        NopClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http:     reqwest::Client::new(),
        }
    }

    pub async fn submit(&self, frame: &TaskFrame) -> NpsResult<String> {
        let body = serde_json::to_vec(&frame.to_dict())
            .map_err(|e| NpsError::Codec(e.to_string()))?;
        let res = self.http.post(format!("{}/tasks", self.base_url))
            .header("Content-Type", "application/json")
            .body(body)
            .send().await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        self.check_ok(res.status(), "/tasks")?;
        let v: serde_json::Value = res.json().await
            .map_err(|e| NpsError::Codec(e.to_string()))?;
        v["task_id"].as_str()
            .map(str::to_string)
            .ok_or_else(|| NpsError::Frame("no task_id in response".into()))
    }

    pub async fn get_status(&self, task_id: &str) -> NpsResult<NopTaskStatus> {
        let res = self.http.get(format!("{}/tasks/{task_id}", self.base_url))
            .send().await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        self.check_ok(res.status(), "/tasks/{id}")?;
        let v: serde_json::Map<String, serde_json::Value> = res.json().await
            .map_err(|e| NpsError::Codec(e.to_string()))?;
        Ok(NopTaskStatus::from_dict(v))
    }

    pub async fn cancel(&self, task_id: &str) -> NpsResult<()> {
        let res = self.http.delete(format!("{}/tasks/{task_id}", self.base_url))
            .send().await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        self.check_ok(res.status(), "/tasks/{id}")
    }

    pub async fn wait(
        &self,
        task_id: &str,
        timeout: std::time::Duration,
        poll_interval: std::time::Duration,
    ) -> NpsResult<NopTaskStatus> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let status = self.get_status(task_id).await?;
            if status.is_terminal() {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NpsError::Io(format!("timeout waiting for task {task_id}")));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    fn check_ok(&self, status: reqwest::StatusCode, path: &str) -> NpsResult<()> {
        if status.is_success() { Ok(()) }
        else { Err(NpsError::Io(format!("NOP {path} failed: HTTP {}", status.as_u16()))) }
    }
}
