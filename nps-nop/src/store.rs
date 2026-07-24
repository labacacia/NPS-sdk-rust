// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Persistence abstraction for NOP task and subtask state (NPS-5 §5). Faithful
//! port of the .NET `INopTaskStore` and `InMemoryNopTaskStore`.

use futures::future::BoxFuture;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::models::TaskState;
use crate::orch_models::TaskFrame;

/// State and result for a single DAG node (subtask).
#[derive(Debug, Clone)]
pub struct NopSubtaskRecord {
    pub node_id: String,
    pub subtask_id: String,
    pub state: TaskState,
    pub result: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub attempt_count: i32,
}

/// Persistent record of a running or completed NOP task.
#[derive(Debug, Clone)]
pub struct NopTaskRecord {
    pub task_id: String,
    pub frame: TaskFrame,
    pub state: TaskState,
    pub started_at_ms: u128,
    pub completed_at_ms: Option<u128>,
    /// Per-node subtask records, keyed by DAG node ID.
    pub subtasks: HashMap<String, NopSubtaskRecord>,
}

/// Parameters passed to [`NopTaskStore::update_subtask`].
#[derive(Debug, Clone, Default)]
pub struct SubtaskUpdate {
    pub result: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub attempt: i32,
}

/// Persistence abstraction for NOP task and subtask state.
pub trait NopTaskStore: Send + Sync {
    /// Persists a new task record. Errors if the task ID already exists.
    fn save<'a>(&'a self, record: NopTaskRecord) -> BoxFuture<'a, Result<(), String>>;

    /// Returns the task record, or `None` if not found.
    fn get<'a>(&'a self, task_id: &'a str) -> BoxFuture<'a, Option<NopTaskRecord>>;

    /// Updates the overall task state.
    fn update_state<'a>(&'a self, task_id: &'a str, state: TaskState) -> BoxFuture<'a, ()>;

    /// Creates or updates a subtask record within the task.
    fn update_subtask<'a>(
        &'a self,
        task_id: &'a str,
        node_id: &'a str,
        subtask_id: &'a str,
        state: TaskState,
        update: SubtaskUpdate,
    ) -> BoxFuture<'a, ()>;
}

/// Volatile, in-memory implementation of [`NopTaskStore`].
#[derive(Default)]
pub struct InMemoryNopTaskStore {
    tasks: Mutex<HashMap<String, NopTaskRecord>>,
}

impl InMemoryNopTaskStore {
    pub fn new() -> Self {
        InMemoryNopTaskStore {
            tasks: Mutex::new(HashMap::new()),
        }
    }
}

impl NopTaskStore for InMemoryNopTaskStore {
    fn save<'a>(&'a self, record: NopTaskRecord) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let mut tasks = self.tasks.lock().unwrap();
            if tasks.contains_key(&record.task_id) {
                return Err(format!("Task already exists: {}", record.task_id));
            }
            tasks.insert(record.task_id.clone(), record);
            Ok(())
        })
    }

    fn get<'a>(&'a self, task_id: &'a str) -> BoxFuture<'a, Option<NopTaskRecord>> {
        Box::pin(async move { self.tasks.lock().unwrap().get(task_id).cloned() })
    }

    fn update_state<'a>(&'a self, task_id: &'a str, state: TaskState) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Some(rec) = self.tasks.lock().unwrap().get_mut(task_id) {
                rec.state = state;
            }
        })
    }

    fn update_subtask<'a>(
        &'a self,
        task_id: &'a str,
        node_id: &'a str,
        subtask_id: &'a str,
        state: TaskState,
        update: SubtaskUpdate,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut tasks = self.tasks.lock().unwrap();
            let Some(rec) = tasks.get_mut(task_id) else {
                return;
            };
            let sub = rec
                .subtasks
                .entry(node_id.to_string())
                .or_insert_with(|| NopSubtaskRecord {
                    node_id: node_id.to_string(),
                    subtask_id: subtask_id.to_string(),
                    state,
                    result: None,
                    error_code: None,
                    error_message: None,
                    attempt_count: 0,
                });
            sub.state = state;
            if update.attempt > 0 {
                sub.attempt_count = update.attempt;
            }
            if update.result.is_some() {
                sub.result = update.result;
            }
            if update.error_code.is_some() {
                sub.error_code = update.error_code;
            }
            if update.error_message.is_some() {
                sub.error_message = update.error_message;
            }
        })
    }
}
