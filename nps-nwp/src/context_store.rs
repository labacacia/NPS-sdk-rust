// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Process-local reference state machine for NWP stateful LLM contexts.

use crate::error_codes;
use crate::{
    LlmContextOperation, LlmContextReceiptDto, LlmContextState, LlmContextStatusDto, LlmMessageDto,
    LlmToolDefinitionDto, LLM_COMPLETE, LLM_CONTEXT_RELEASE,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const INTERNAL_ERROR: &str = "NPS-SERVER-INTERNAL";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LlmContextOwner {
    pub nid: String,
    pub security_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LlmContextBinding {
    pub model: String,
    pub system_messages: Vec<LlmMessageDto>,
    pub tools: Vec<LlmToolDefinitionDto>,
    pub runtime_revision: String,
}

#[derive(Debug, Clone)]
pub struct LlmContextMutationRequest {
    pub operation: LlmContextOperation,
    pub owner: LlmContextOwner,
    pub context_id: Option<String>,
    pub base_version: Option<u64>,
    pub binding: LlmContextBinding,
    pub messages: Vec<LlmMessageDto>,
    pub ttl_seconds: Option<u32>,
    pub idempotency_key: String,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct LlmContextMutationReservation {
    reservation_id: String,
    operation: LlmContextOperation,
    request_id: String,
}

impl LlmContextMutationReservation {
    pub fn operation(&self) -> LlmContextOperation {
        self.operation
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmContextSnapshot {
    pub context_id: String,
    pub version: u64,
    pub state: LlmContextState,
    pub transcript: Vec<LlmMessageDto>,
    pub binding: LlmContextBinding,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct LlmContextStoreError {
    pub error_code: String,
    pub message: String,
    pub current_version: Option<u64>,
}

type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;
type ContextIdFactory = Arc<dyn Fn() -> Result<String, LlmContextStoreError> + Send + Sync>;

pub struct LlmContextStoreOptions {
    pub max_contexts_per_principal: u32,
    pub default_ttl_seconds: u32,
    pub max_ttl_seconds: u32,
    pub tombstone_seconds: u32,
    pub idempotency_ttl: Duration,
    pub supported_operations: Option<HashSet<LlmContextOperation>>,
    pub clock: Clock,
    pub context_id_factory: ContextIdFactory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmContextStoreDescriptor {
    pub operations: Vec<LlmContextOperation>,
    pub persistence: &'static str,
    pub max_contexts_per_principal: u32,
    pub max_ttl_seconds: u32,
    pub tombstone_seconds: u32,
}

impl Default for LlmContextStoreOptions {
    fn default() -> Self {
        Self {
            max_contexts_per_principal: 32,
            default_ttl_seconds: 3600,
            max_ttl_seconds: 3600,
            tombstone_seconds: 86_400,
            idempotency_ttl: Duration::hours(24),
            supported_operations: None,
            clock: Arc::new(OffsetDateTime::now_utc),
            context_id_factory: Arc::new(new_context_id),
        }
    }
}

impl LlmContextStoreOptions {
    fn normalized(mut self) -> Self {
        if self.max_contexts_per_principal == 0 {
            self.max_contexts_per_principal = 32;
        }
        if self.default_ttl_seconds == 0 {
            self.default_ttl_seconds = 3600;
        }
        if self.max_ttl_seconds == 0 {
            self.max_ttl_seconds = 3600;
        }
        if self.tombstone_seconds == 0 {
            self.tombstone_seconds = 86_400;
        }
        if self.idempotency_ttl <= Duration::ZERO {
            self.idempotency_ttl = Duration::hours(24);
        }
        if self.supported_operations.is_none() {
            self.supported_operations = Some(HashSet::from([
                LlmContextOperation::Create,
                LlmContextOperation::Append,
                LlmContextOperation::Fork,
                LlmContextOperation::Reset,
                LlmContextOperation::Release,
            ]));
        }
        self
    }
}

struct ContextEntry {
    context_id: String,
    owner: LlmContextOwner,
    version: u64,
    state: LlmContextState,
    binding: LlmContextBinding,
    binding_fingerprint: String,
    transcript: Vec<LlmMessageDto>,
    ttl_seconds: u32,
    expires_at: Option<OffsetDateTime>,
    tombstone_until: Option<OffsetDateTime>,
    reservation_id: Option<String>,
}

#[derive(Clone)]
struct ReservationData {
    reservation_id: String,
    request: LlmContextMutationRequest,
    binding_fingerprint: String,
    base_transcript: Vec<LlmMessageDto>,
    effective_ttl_seconds: Option<u32>,
    parent_context_id: Option<String>,
    parent_version: Option<u64>,
}

#[derive(Clone)]
struct IdempotencyEntry {
    state: OutcomeState,
    retain_until: OffsetDateTime,
    request_id: Option<String>,
    error_code: Option<String>,
    receipt: Option<LlmContextReceiptDto>,
    context_id: Option<String>,
    base_version: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutcomeState {
    Busy,
    Completed,
    Failed,
}

#[derive(Default)]
struct StoreState {
    contexts: HashMap<String, ContextEntry>,
    idempotency: HashMap<IdempotencyKey, IdempotencyEntry>,
    reservations: HashMap<String, ReservationData>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct IdempotencyKey {
    owner: LlmContextOwner,
    action: &'static str,
    key: String,
}

pub struct InMemoryLlmContextStore {
    options: LlmContextStoreOptions,
    state: Mutex<StoreState>,
}

impl InMemoryLlmContextStore {
    pub fn new(options: LlmContextStoreOptions) -> Self {
        Self {
            options: options.normalized(),
            state: Mutex::new(StoreState::default()),
        }
    }

    /// Discovery values that this process-local store can truthfully advertise.
    pub fn descriptor(&self) -> LlmContextStoreDescriptor {
        let supported = self
            .options
            .supported_operations
            .as_ref()
            .expect("options normalized");
        let operations = [
            LlmContextOperation::Create,
            LlmContextOperation::Append,
            LlmContextOperation::Fork,
            LlmContextOperation::Reset,
            LlmContextOperation::Release,
        ]
        .into_iter()
        .filter(|operation| supported.contains(operation))
        .collect();
        LlmContextStoreDescriptor {
            operations,
            persistence: "process",
            max_contexts_per_principal: self.options.max_contexts_per_principal,
            max_ttl_seconds: self.options.max_ttl_seconds,
            tombstone_seconds: self.options.tombstone_seconds,
        }
    }

    pub fn reserve(
        &self,
        request: LlmContextMutationRequest,
    ) -> Result<LlmContextMutationReservation, LlmContextStoreError> {
        let mut state = self.lock()?;
        let now = self.now();
        self.sweep_locked(&mut state, now);
        self.validate_request(&request)?;
        self.ensure_supported(request.operation)?;

        let outcome_key = idempotency_key(&request.owner, LLM_COMPLETE, &request.idempotency_key);
        if state.idempotency.contains_key(&outcome_key) {
            return Err(store_error(
                error_codes::ACTION_IDEMPOTENCY_CONFLICT,
                "an outcome already exists for this idempotency key",
                None,
            ));
        }

        let (base_transcript, effective_ttl_seconds, parent_context_id, parent_version) =
            if request.operation == LlmContextOperation::Create {
                self.ensure_allocation_available(&state, &request.owner)?;
                (
                    Vec::new(),
                    Some(
                        self.clamp_ttl(
                            request
                                .ttl_seconds
                                .unwrap_or(self.options.default_ttl_seconds),
                        ),
                    ),
                    None,
                    None,
                )
            } else {
                let context_id = request.context_id.as_deref().expect("validated context_id");
                let base_version = request.base_version.expect("validated base_version");
                let entry = require_mutable(&state, &request.owner, context_id)?;
                if entry.reservation_id.is_some() || entry.version != base_version {
                    return Err(store_error(
                        error_codes::LLM_CONTEXT_VERSION_CONFLICT,
                        "the context version is stale or a mutation is running",
                        Some(entry.version),
                    ));
                }
                let fingerprint = binding_fingerprint(&request.binding)?;
                if matches!(
                    request.operation,
                    LlmContextOperation::Append | LlmContextOperation::Fork
                ) && entry.binding_fingerprint != fingerprint
                {
                    return Err(store_error(
                        error_codes::LLM_CONTEXT_BINDING_MISMATCH,
                        "the request binding differs from the retained binding",
                        None,
                    ));
                }
                if request.operation == LlmContextOperation::Fork {
                    self.ensure_allocation_available(&state, &request.owner)?;
                }
                let ttl = self.effective_ttl(&request, entry, now);
                (
                    entry.transcript.clone(),
                    ttl,
                    (request.operation == LlmContextOperation::Fork)
                        .then(|| entry.context_id.clone()),
                    (request.operation == LlmContextOperation::Fork).then_some(entry.version),
                )
            };

        let reservation_id = new_reservation_id()?;
        let data = ReservationData {
            reservation_id: reservation_id.clone(),
            binding_fingerprint: binding_fingerprint(&request.binding)?,
            request: request.clone(),
            base_transcript,
            effective_ttl_seconds,
            parent_context_id,
            parent_version,
        };
        if request.operation != LlmContextOperation::Create
            && request.operation != LlmContextOperation::Fork
        {
            state
                .contexts
                .get_mut(request.context_id.as_deref().expect("validated context_id"))
                .expect("validated context")
                .reservation_id = Some(reservation_id.clone());
        }
        state.reservations.insert(reservation_id.clone(), data);
        state.idempotency.insert(
            outcome_key,
            IdempotencyEntry {
                state: OutcomeState::Busy,
                retain_until: now + self.options.idempotency_ttl,
                request_id: nonempty(&request.request_id),
                error_code: None,
                receipt: None,
                context_id: None,
                base_version: None,
            },
        );
        Ok(LlmContextMutationReservation {
            reservation_id,
            operation: request.operation,
            request_id: request.request_id,
        })
    }

    pub fn commit(
        &self,
        reservation: &LlmContextMutationReservation,
        assistant_result: LlmMessageDto,
    ) -> Result<LlmContextReceiptDto, LlmContextStoreError> {
        let mut state = self.lock()?;
        let current = require_reservation(&state, reservation)?.clone();
        let now = self.now();
        let expiry = current
            .effective_ttl_seconds
            .map(|seconds| now + Duration::seconds(i64::from(seconds)));

        let (context_id, version) = match current.request.operation {
            LlmContextOperation::Create | LlmContextOperation::Fork => {
                let context_id = self.next_context_id(&state)?;
                let mut transcript = if current.request.operation == LlmContextOperation::Fork {
                    current.base_transcript.clone()
                } else {
                    Vec::new()
                };
                transcript.extend(current.request.messages.clone());
                transcript.push(assistant_result);
                state.contexts.insert(
                    context_id.clone(),
                    ContextEntry {
                        context_id: context_id.clone(),
                        owner: current.request.owner.clone(),
                        version: 1,
                        state: LlmContextState::Active,
                        binding: current.request.binding.clone(),
                        binding_fingerprint: current.binding_fingerprint.clone(),
                        transcript,
                        ttl_seconds: current.effective_ttl_seconds.unwrap_or(0),
                        expires_at: expiry,
                        tombstone_until: None,
                        reservation_id: None,
                    },
                );
                (context_id, 1)
            }
            LlmContextOperation::Append | LlmContextOperation::Reset => {
                let context_id = current
                    .request
                    .context_id
                    .as_deref()
                    .expect("reserved context_id");
                let entry = state.contexts.get_mut(context_id).ok_or_else(not_found)?;
                entry.version += 1;
                entry.state = LlmContextState::Active;
                entry.reservation_id = None;
                entry.expires_at = expiry;
                entry.ttl_seconds = current.effective_ttl_seconds.unwrap_or(0);
                if current.request.operation == LlmContextOperation::Reset {
                    entry.binding = current.request.binding.clone();
                    entry.binding_fingerprint = current.binding_fingerprint.clone();
                    entry.transcript = current.request.messages.clone();
                } else {
                    entry.transcript.extend(current.request.messages.clone());
                }
                entry.transcript.push(assistant_result);
                (entry.context_id.clone(), entry.version)
            }
            LlmContextOperation::Release => unreachable!("release cannot be reserved"),
        };

        let receipt = LlmContextReceiptDto {
            context_id,
            version,
            operation: current.request.operation,
            state: LlmContextState::Active,
            expires_at: expiry.and_then(format_time),
            parent_context_id: current.parent_context_id.clone(),
            parent_version: current.parent_version,
        };
        state.idempotency.insert(
            idempotency_key(
                &current.request.owner,
                LLM_COMPLETE,
                &current.request.idempotency_key,
            ),
            IdempotencyEntry {
                state: OutcomeState::Completed,
                retain_until: now + self.options.idempotency_ttl,
                request_id: nonempty(&current.request.request_id),
                error_code: None,
                receipt: Some(receipt.clone()),
                context_id: None,
                base_version: None,
            },
        );
        state.reservations.remove(&current.reservation_id);
        Ok(receipt)
    }

    pub fn abort(
        &self,
        reservation: &LlmContextMutationReservation,
        error_code: Option<&str>,
    ) -> Result<(), LlmContextStoreError> {
        let mut state = self.lock()?;
        let current = require_reservation(&state, reservation)?.clone();
        clear_reservation(&mut state, &current);
        state.reservations.remove(&current.reservation_id);
        let now = self.now();
        state.idempotency.insert(
            idempotency_key(
                &current.request.owner,
                LLM_COMPLETE,
                &current.request.idempotency_key,
            ),
            IdempotencyEntry {
                state: OutcomeState::Failed,
                retain_until: now + self.options.idempotency_ttl,
                request_id: nonempty(&current.request.request_id),
                error_code: error_code.map(str::to_owned),
                receipt: None,
                context_id: None,
                base_version: None,
            },
        );
        self.sweep_locked(&mut state, now);
        Ok(())
    }

    pub fn release(
        &self,
        owner: &LlmContextOwner,
        context_id: &str,
        base_version: u64,
        idempotency: &str,
    ) -> Result<LlmContextReceiptDto, LlmContextStoreError> {
        let mut state = self.lock()?;
        let now = self.now();
        self.sweep_locked(&mut state, now);
        self.ensure_supported(LlmContextOperation::Release)?;
        validate_context_id(context_id)?;
        if idempotency.trim().is_empty() {
            return Err(params_invalid("release requires idempotency_key"));
        }
        let key = idempotency_key(owner, LLM_CONTEXT_RELEASE, idempotency);
        if let Some(prior) = state.idempotency.get(&key) {
            if prior.state == OutcomeState::Completed
                && prior.context_id.as_deref() == Some(context_id)
                && prior.base_version == Some(base_version)
            {
                return prior
                    .receipt
                    .clone()
                    .ok_or_else(|| internal_error("completed release outcome has no receipt"));
            }
            return Err(store_error(
                error_codes::ACTION_IDEMPOTENCY_CONFLICT,
                "a release with this idempotency key already exists",
                None,
            ));
        }
        let entry = require_mutable_mut(&mut state, owner, context_id)?;
        if entry.reservation_id.is_some() || entry.version != base_version {
            return Err(store_error(
                error_codes::LLM_CONTEXT_VERSION_CONFLICT,
                "the context version is stale or a mutation is running",
                Some(entry.version),
            ));
        }
        entry.version += 1;
        entry.state = LlmContextState::Released;
        entry.expires_at = None;
        entry.tombstone_until =
            Some(now + Duration::seconds(i64::from(self.options.tombstone_seconds)));
        let receipt = LlmContextReceiptDto {
            context_id: context_id.to_owned(),
            version: entry.version,
            operation: LlmContextOperation::Release,
            state: LlmContextState::Released,
            expires_at: None,
            parent_context_id: None,
            parent_version: None,
        };
        state.idempotency.insert(
            key,
            IdempotencyEntry {
                state: OutcomeState::Completed,
                retain_until: now + self.options.idempotency_ttl,
                request_id: None,
                error_code: None,
                receipt: Some(receipt.clone()),
                context_id: Some(context_id.to_owned()),
                base_version: Some(base_version),
            },
        );
        Ok(receipt)
    }

    pub fn status(
        &self,
        owner: &LlmContextOwner,
        context_id: Option<&str>,
        idempotency: Option<&str>,
    ) -> Result<LlmContextStatusDto, LlmContextStoreError> {
        let mut state = self.lock()?;
        self.sweep_locked(&mut state, self.now());
        if context_id.is_some() == idempotency.is_some() {
            return Err(params_invalid("status requires exactly one locator"));
        }
        if let Some(idempotency) = idempotency {
            let outcome = state
                .idempotency
                .get(&idempotency_key(owner, LLM_COMPLETE, idempotency))
                .ok_or_else(not_found)?;
            return match outcome.state {
                OutcomeState::Busy => Ok(LlmContextStatusDto {
                    state: LlmContextState::Busy,
                    context_id: None,
                    version: None,
                    expires_at: None,
                    request_id: outcome.request_id.clone(),
                    error_code: None,
                }),
                OutcomeState::Failed => Ok(LlmContextStatusDto {
                    state: LlmContextState::Failed,
                    context_id: None,
                    version: None,
                    expires_at: None,
                    request_id: outcome.request_id.clone(),
                    error_code: outcome.error_code.clone(),
                }),
                OutcomeState::Completed => {
                    let receipt = outcome.receipt.clone().ok_or_else(|| {
                        internal_error("completed context outcome has no receipt")
                    })?;
                    status_from_receipt(&state, owner, &receipt)
                }
            };
        }
        status_by_context(&state, owner, context_id.expect("one locator validated"))
    }

    pub fn snapshot(
        &self,
        owner: &LlmContextOwner,
        context_id: &str,
    ) -> Result<LlmContextSnapshot, LlmContextStoreError> {
        let mut state = self.lock()?;
        self.sweep_locked(&mut state, self.now());
        let entry = require_mutable(&state, owner, context_id)?;
        Ok(LlmContextSnapshot {
            context_id: entry.context_id.clone(),
            version: entry.version,
            state: entry.state,
            transcript: entry.transcript.clone(),
            binding: entry.binding.clone(),
            expires_at: entry.expires_at,
        })
    }

    pub fn sweep_expired(&self) -> Result<usize, LlmContextStoreError> {
        let mut state = self.lock()?;
        Ok(self.sweep_locked(&mut state, self.now()))
    }

    fn validate_request(
        &self,
        request: &LlmContextMutationRequest,
    ) -> Result<(), LlmContextStoreError> {
        if request.operation == LlmContextOperation::Release {
            return Err(params_invalid("release uses the lifecycle action"));
        }
        if request.idempotency_key.trim().is_empty() {
            return Err(params_invalid(
                "a stateful request requires idempotency_key",
            ));
        }
        if request.ttl_seconds == Some(0) {
            return Err(params_invalid("ttl_seconds must be greater than zero"));
        }
        if request.operation == LlmContextOperation::Create {
            if request.context_id.is_some() || request.base_version.is_some() {
                return Err(params_invalid("create forbids context_id and base_version"));
            }
        } else {
            let context_id = request.context_id.as_deref().ok_or_else(|| {
                params_invalid("append/fork/reset require context_id and base_version")
            })?;
            if request.base_version.is_none() {
                return Err(params_invalid(
                    "append/fork/reset require context_id and base_version",
                ));
            }
            validate_context_id(context_id)?;
        }
        if request.operation != LlmContextOperation::Fork && request.messages.is_empty() {
            return Err(params_invalid("only fork may carry an empty message delta"));
        }
        if matches!(
            request.operation,
            LlmContextOperation::Append | LlmContextOperation::Fork
        ) && request
            .messages
            .iter()
            .any(|message| message.role.eq_ignore_ascii_case("system"))
        {
            return Err(store_error(
                error_codes::LLM_CONTEXT_BINDING_MISMATCH,
                "append/fork deltas must not contain system messages",
                None,
            ));
        }
        Ok(())
    }

    fn ensure_supported(&self, operation: LlmContextOperation) -> Result<(), LlmContextStoreError> {
        if !self
            .options
            .supported_operations
            .as_ref()
            .expect("options normalized")
            .contains(&operation)
        {
            return Err(store_error(
                error_codes::LLM_CONTEXT_OPERATION_UNSUPPORTED,
                "context operation is not advertised",
                None,
            ));
        }
        Ok(())
    }

    fn ensure_allocation_available(
        &self,
        state: &StoreState,
        owner: &LlmContextOwner,
    ) -> Result<(), LlmContextStoreError> {
        let live = state
            .contexts
            .values()
            .filter(|entry| entry.owner == *owner && entry.state == LlmContextState::Active)
            .count();
        let pending = state
            .reservations
            .values()
            .filter(|reservation| {
                reservation.request.owner == *owner
                    && matches!(
                        reservation.request.operation,
                        LlmContextOperation::Create | LlmContextOperation::Fork
                    )
            })
            .count();
        if live + pending >= self.options.max_contexts_per_principal as usize {
            return Err(store_error(
                error_codes::LLM_CONTEXT_LIMIT_EXCEEDED,
                "the principal's live context limit has been reached",
                None,
            ));
        }
        Ok(())
    }

    fn effective_ttl(
        &self,
        request: &LlmContextMutationRequest,
        entry: &ContextEntry,
        now: OffsetDateTime,
    ) -> Option<u32> {
        if let Some(value) = request.ttl_seconds {
            return Some(self.clamp_ttl(value));
        }
        if request.operation == LlmContextOperation::Fork {
            return entry.expires_at.map(|expires_at| {
                let nanos = (expires_at - now).whole_nanoseconds();
                let seconds = ((nanos + 999_999_999) / 1_000_000_000).max(1);
                seconds.min(i128::from(u32::MAX)) as u32
            });
        }
        (entry.ttl_seconds != 0).then_some(entry.ttl_seconds)
    }

    fn next_context_id(&self, state: &StoreState) -> Result<String, LlmContextStoreError> {
        for _ in 0..8 {
            let value = (self.options.context_id_factory)()?;
            validate_context_id(&value)?;
            if !state.contexts.contains_key(&value) {
                return Ok(value);
            }
        }
        Err(internal_error(
            "context ID factory repeatedly produced collisions",
        ))
    }

    fn sweep_locked(&self, state: &mut StoreState, now: OffsetDateTime) -> usize {
        let mut changed = 0;
        for entry in state.contexts.values_mut() {
            if entry.state == LlmContextState::Active
                && entry.reservation_id.is_none()
                && entry.expires_at.is_some_and(|expires_at| expires_at <= now)
            {
                entry.state = LlmContextState::Expired;
                entry.expires_at = None;
                entry.tombstone_until =
                    Some(now + Duration::seconds(i64::from(self.options.tombstone_seconds)));
                changed += 1;
            }
        }
        let before = state.contexts.len();
        state.contexts.retain(|_, entry| {
            !matches!(
                entry.state,
                LlmContextState::Expired | LlmContextState::Released
            ) || entry.tombstone_until.is_none_or(|until| until > now)
        });
        changed += before - state.contexts.len();
        let before = state.idempotency.len();
        state
            .idempotency
            .retain(|_, outcome| outcome.state == OutcomeState::Busy || outcome.retain_until > now);
        changed + before - state.idempotency.len()
    }

    fn clamp_ttl(&self, value: u32) -> u32 {
        value.min(self.options.max_ttl_seconds)
    }

    fn now(&self) -> OffsetDateTime {
        (self.options.clock)()
    }

    fn lock(&self) -> Result<MutexGuard<'_, StoreState>, LlmContextStoreError> {
        self.state
            .lock()
            .map_err(|_| internal_error("LLM context store lock was poisoned"))
    }
}

impl Default for InMemoryLlmContextStore {
    fn default() -> Self {
        Self::new(LlmContextStoreOptions::default())
    }
}

fn require_mutable<'a>(
    state: &'a StoreState,
    owner: &LlmContextOwner,
    context_id: &str,
) -> Result<&'a ContextEntry, LlmContextStoreError> {
    let entry = state.contexts.get(context_id).ok_or_else(not_found)?;
    ensure_owner(entry, owner)?;
    match entry.state {
        LlmContextState::Expired => Err(store_error(
            error_codes::LLM_CONTEXT_EXPIRED,
            "the context expired",
            Some(entry.version),
        )),
        LlmContextState::Released => Err(not_found()),
        _ => Ok(entry),
    }
}

fn require_mutable_mut<'a>(
    state: &'a mut StoreState,
    owner: &LlmContextOwner,
    context_id: &str,
) -> Result<&'a mut ContextEntry, LlmContextStoreError> {
    let entry = state.contexts.get_mut(context_id).ok_or_else(not_found)?;
    ensure_owner(entry, owner)?;
    match entry.state {
        LlmContextState::Expired => Err(store_error(
            error_codes::LLM_CONTEXT_EXPIRED,
            "the context expired",
            Some(entry.version),
        )),
        LlmContextState::Released => Err(not_found()),
        _ => Ok(entry),
    }
}

fn ensure_owner(entry: &ContextEntry, owner: &LlmContextOwner) -> Result<(), LlmContextStoreError> {
    if entry.owner != *owner {
        return Err(store_error(
            error_codes::LLM_CONTEXT_FORBIDDEN,
            "the caller does not own this context",
            None,
        ));
    }
    Ok(())
}

fn require_reservation<'a>(
    state: &'a StoreState,
    reservation: &LlmContextMutationReservation,
) -> Result<&'a ReservationData, LlmContextStoreError> {
    let current = state
        .reservations
        .get(&reservation.reservation_id)
        .ok_or_else(|| internal_error("context reservation is not active"))?;
    if current.reservation_id != reservation.reservation_id {
        return Err(internal_error("context reservation identity mismatch"));
    }
    Ok(current)
}

fn clear_reservation(state: &mut StoreState, reservation: &ReservationData) {
    if let Some(context_id) = reservation.request.context_id.as_deref() {
        if let Some(entry) = state.contexts.get_mut(context_id) {
            if entry.reservation_id.as_deref() == Some(&reservation.reservation_id) {
                entry.reservation_id = None;
            }
        }
    }
}

fn status_from_receipt(
    state: &StoreState,
    owner: &LlmContextOwner,
    receipt: &LlmContextReceiptDto,
) -> Result<LlmContextStatusDto, LlmContextStoreError> {
    if state.contexts.contains_key(&receipt.context_id) {
        return status_by_context(state, owner, &receipt.context_id);
    }
    Ok(LlmContextStatusDto {
        state: receipt.state,
        context_id: Some(receipt.context_id.clone()),
        version: Some(receipt.version),
        expires_at: receipt.expires_at.clone(),
        request_id: None,
        error_code: None,
    })
}

fn status_by_context(
    state: &StoreState,
    owner: &LlmContextOwner,
    context_id: &str,
) -> Result<LlmContextStatusDto, LlmContextStoreError> {
    validate_context_id(context_id)?;
    let entry = state.contexts.get(context_id).ok_or_else(not_found)?;
    ensure_owner(entry, owner)?;
    let request_id = entry
        .reservation_id
        .as_ref()
        .and_then(|id| state.reservations.get(id))
        .and_then(|reservation| nonempty(&reservation.request.request_id));
    Ok(LlmContextStatusDto {
        state: if entry.reservation_id.is_some() {
            LlmContextState::Busy
        } else {
            entry.state
        },
        context_id: Some(entry.context_id.clone()),
        version: Some(entry.version),
        expires_at: entry.expires_at.and_then(format_time),
        request_id,
        error_code: None,
    })
}

fn binding_fingerprint(binding: &LlmContextBinding) -> Result<String, LlmContextStoreError> {
    let encoded = serde_json::to_vec(binding)
        .map_err(|error| internal_error(&format!("serialize context binding: {error}")))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn new_context_id() -> Result<String, LlmContextStoreError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| internal_error(&format!("generate context ID: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn new_reservation_id() -> Result<String, LlmContextStoreError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| internal_error(&format!("generate reservation ID: {error}")))?;
    Ok(hex::encode(bytes))
}

fn validate_context_id(value: &str) -> Result<(), LlmContextStoreError> {
    let valid = (22..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if !valid {
        return Err(params_invalid(
            "context_id must be a 22-128 character unpadded base64url locator",
        ));
    }
    Ok(())
}

fn idempotency_key(owner: &LlmContextOwner, action: &'static str, key: &str) -> IdempotencyKey {
    IdempotencyKey {
        owner: owner.clone(),
        action,
        key: key.to_owned(),
    }
}

fn format_time(value: OffsetDateTime) -> Option<String> {
    value.format(&Rfc3339).ok()
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn params_invalid(message: &str) -> LlmContextStoreError {
    store_error(error_codes::ACTION_PARAMS_INVALID, message, None)
}

fn not_found() -> LlmContextStoreError {
    store_error(
        error_codes::LLM_CONTEXT_NOT_FOUND,
        "context or retained outcome not found",
        None,
    )
}

fn internal_error(message: &str) -> LlmContextStoreError {
    store_error(INTERNAL_ERROR, message, None)
}

fn store_error(
    error_code: &str,
    message: &str,
    current_version: Option<u64>,
) -> LlmContextStoreError {
    LlmContextStoreError {
        error_code: error_code.to_owned(),
        message: message.to_owned(),
        current_version,
    }
}
