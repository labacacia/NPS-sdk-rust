// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Failover reconnect / session continuity for the NCP native path
//! (NPS-CR-0009 §3.3).
//!
//! Port of `impl/dotnet/src/NPS.Core/Ncp/NcpFailoverConnector.cs`. The .NET
//! reference expresses "is this failure failover-shaped?" with an exception
//! type test; Rust uses `Result<S, E>` plus an injected **matcher closure**, so
//! the connector stays generic over both the session type and the error type
//! without a shared error trait.
//!
//! Both the resolver and the connect step are injected, so the connector has no
//! NDP dependency: the caller composes it with either NDP highest-epoch
//! resolution (§3.1) or the `successor_nid` of a received `anchor_failover`.
//!
//! ```
//! use nps_ncp::failover::NcpFailoverConnector;
//! use std::cell::Cell;
//!
//! let attempt = Cell::new(0);
//! let connector = NcpFailoverConnector::new(
//!     || {
//!         attempt.set(attempt.get() + 1);
//!         Ok(if attempt.get() == 1 {
//!             ("old-anchor".to_string(), 17433)
//!         } else {
//!             ("new-anchor".to_string(), 17433)
//!         })
//!     },
//!     |host: &str, _port| {
//!         if host == "old-anchor" {
//!             Err("NCP-NID-MISMATCH".to_string())
//!         } else {
//!             Ok(host.to_string())
//!         }
//!     },
//!     |e: &String| e == "NCP-NID-MISMATCH",
//! )
//! .unwrap();
//!
//! assert_eq!(connector.connect().unwrap(), "new-anchor");
//! ```

use crate::error_codes::NID_MISMATCH;

/// Default number of connect attempts. `max_attempts = 2` performs exactly two
/// resolutions on a single failure — the re-resolution is what picks up the new
/// active Anchor.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 2;

/// Construction faults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverConfigError {
    MaxAttemptsTooSmall(u32),
}

impl std::fmt::Display for FailoverConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailoverConfigError::MaxAttemptsTooSmall(n) => {
                write!(f, "max_attempts must be >= 1, got {n}")
            }
        }
    }
}

impl std::error::Error for FailoverConfigError {}

/// Outcome of [`NcpFailoverConnector::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverError<E> {
    /// The last captured failure, rethrown after every attempt was spent. The
    /// original error value is preserved, not wrapped in a new type.
    Exhausted(E),
    /// The active-Anchor resolution itself failed on some attempt.
    Resolve(E),
}

impl<E: std::fmt::Debug> std::fmt::Display for FailoverError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailoverError::Exhausted(e) => {
                write!(f, "all failover attempts exhausted: {e:?}")
            }
            FailoverError::Resolve(e) => {
                write!(f, "resolving the active Anchor failed: {e:?}")
            }
        }
    }
}

impl<E: std::fmt::Debug> std::error::Error for FailoverError<E> {}

impl<E> FailoverError<E> {
    /// The underlying error, whichever arm carried it.
    pub fn into_inner(self) -> E {
        match self {
            FailoverError::Exhausted(e) | FailoverError::Resolve(e) => e,
        }
    }
}

/// Reconnects a native NCP session across an Anchor failover.
///
/// Generic in the session type: it wraps TCP, TLS, or a test double
/// identically, and never names a concrete client type.
pub struct NcpFailoverConnector<S, E, R, C, M>
where
    R: Fn() -> Result<(String, u16), E>,
    C: Fn(&str, u16) -> Result<S, E>,
    M: Fn(&E) -> bool,
{
    resolve_active: R,
    connect_fn: C,
    is_failover_shaped: M,
    max_attempts: u32,
    _marker: std::marker::PhantomData<(S, E)>,
}

impl<S, E, R, C, M> NcpFailoverConnector<S, E, R, C, M>
where
    R: Fn() -> Result<(String, u16), E>,
    C: Fn(&str, u16) -> Result<S, E>,
    M: Fn(&E) -> bool,
{
    /// Build a connector with the default attempt budget.
    pub fn new(
        resolve_active: R,
        connect_fn: C,
        is_failover_shaped: M,
    ) -> Result<Self, FailoverConfigError> {
        Self::with_max_attempts(
            resolve_active,
            connect_fn,
            is_failover_shaped,
            DEFAULT_MAX_ATTEMPTS,
        )
    }

    pub fn with_max_attempts(
        resolve_active: R,
        connect_fn: C,
        is_failover_shaped: M,
        max_attempts: u32,
    ) -> Result<Self, FailoverConfigError> {
        if max_attempts < 1 {
            return Err(FailoverConfigError::MaxAttemptsTooSmall(max_attempts));
        }
        Ok(NcpFailoverConnector {
            resolve_active,
            connect_fn,
            is_failover_shaped,
            max_attempts,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Connect, re-resolving the active Anchor **before every attempt,
    /// including the first**.
    ///
    /// A failover-shaped failure is captured and retried; **any other failure
    /// propagates immediately, unwrapped and unretried**. On exhaustion the
    /// LAST captured failure is returned, with its original type intact.
    pub fn connect(&self) -> Result<S, FailoverError<E>> {
        let mut last: Option<E> = None;
        for _ in 0..self.max_attempts {
            // Re-resolved every attempt — this is what picks up the successor.
            let (host, port) = (self.resolve_active)().map_err(FailoverError::Resolve)?;
            match (self.connect_fn)(&host, port) {
                Ok(session) => return Ok(session),
                Err(e) if (self.is_failover_shaped)(&e) => last = Some(e),
                // Not failover-shaped: no retry, no wrapping.
                Err(e) => return Err(FailoverError::Exhausted(e)),
            }
        }
        Err(FailoverError::Exhausted(last.expect(
            "max_attempts >= 1 guarantees at least one captured failure",
        )))
    }
}

/// Convenience matcher for callers whose error type is a plain NPS protocol
/// error code string: true for `NCP-NID-MISMATCH`.
///
/// Transport-level faults (a refused connection, an I/O error, a timeout) are
/// also failover-shaped, but their representation is caller-specific in Rust —
/// compose this with your own transport test.
pub fn is_nid_mismatch(protocol_error_code: &str) -> bool {
    protocol_error_code == NID_MISMATCH
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A test error mirroring the two shapes the reference distinguishes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TestError {
        /// A socket / I/O failure — always failover-shaped.
        Socket(&'static str),
        /// An NPS protocol error — failover-shaped only for NCP-NID-MISMATCH.
        Nps(&'static str),
    }

    fn shaped(e: &TestError) -> bool {
        match e {
            TestError::Socket(_) => true,
            TestError::Nps(code) => is_nid_mismatch(code),
        }
    }

    struct Resolver {
        hosts: RefCell<Vec<&'static str>>,
        calls: RefCell<u32>,
    }

    impl Resolver {
        fn new(hosts: &[&'static str]) -> Self {
            Resolver {
                hosts: RefCell::new(hosts.to_vec()),
                calls: RefCell::new(0),
            }
        }
        fn next(&self) -> Result<(String, u16), TestError> {
            *self.calls.borrow_mut() += 1;
            let mut h = self.hosts.borrow_mut();
            let host = if h.len() > 1 { h.remove(0) } else { h[0] };
            Ok((host.to_string(), 17433))
        }
        fn calls(&self) -> u32 {
            *self.calls.borrow()
        }
    }

    #[test]
    fn reresolves_and_reconnects_after_nid_mismatch() {
        let r = Resolver::new(&["old-anchor", "new-anchor"]);
        let c = NcpFailoverConnector::new(
            || r.next(),
            |host: &str, _p| {
                if host == "old-anchor" {
                    Err(TestError::Nps("NCP-NID-MISMATCH"))
                } else {
                    Ok(host.to_string())
                }
            },
            shaped,
        )
        .unwrap();

        assert_eq!(c.connect().unwrap(), "new-anchor");
        // BOTH resolutions consumed.
        assert_eq!(r.calls(), 2);
    }

    #[test]
    fn reresolves_after_socket_loss() {
        let r = Resolver::new(&["anchor-1", "anchor-2"]);
        let c = NcpFailoverConnector::new(
            || r.next(),
            |host: &str, _p| {
                if host == "anchor-1" {
                    Err(TestError::Socket("connection refused"))
                } else {
                    Ok(host.to_string())
                }
            },
            shaped,
        )
        .unwrap();

        assert_eq!(c.connect().unwrap(), "anchor-2");
        assert_eq!(r.calls(), 2, "resolve called exactly twice");
    }

    #[test]
    fn non_failover_errors_propagate_immediately() {
        let r = Resolver::new(&["anchor-1", "anchor-2"]);
        let c = NcpFailoverConnector::new(
            || r.next(),
            |_h: &str, _p| Err::<String, _>(TestError::Nps("NCP-FRAME-FLAGS-INVALID")),
            shaped,
        )
        .unwrap();

        let e = c.connect().unwrap_err().into_inner();
        // Original type preserved, unwrapped.
        assert_eq!(e, TestError::Nps("NCP-FRAME-FLAGS-INVALID"));
        // No retry ⇒ resolve called exactly ONCE.
        assert_eq!(r.calls(), 1);
    }

    #[test]
    fn exhausted_attempts_rethrow_the_last_failure() {
        let r = Resolver::new(&["anchor-1"]);
        let attempt = RefCell::new(0);
        let c = NcpFailoverConnector::with_max_attempts(
            || r.next(),
            |_h: &str, _p| {
                *attempt.borrow_mut() += 1;
                Err::<String, _>(TestError::Socket(match *attempt.borrow() {
                    1 => "first",
                    2 => "second",
                    _ => "timeout",
                }))
            },
            shaped,
            3,
        )
        .unwrap();

        let e = c.connect().unwrap_err().into_inner();
        // The LAST failure, not the first.
        assert_eq!(e, TestError::Socket("timeout"));
        assert_eq!(r.calls(), 3);
    }

    #[test]
    fn resolve_runs_once_per_attempt_including_the_first() {
        let r = Resolver::new(&["a"]);
        let c = NcpFailoverConnector::new(|| r.next(), |h: &str, _p| Ok(h.to_string()), shaped)
            .unwrap();
        assert_eq!(c.connect().unwrap(), "a");
        // Success on the first attempt still resolved exactly once.
        assert_eq!(r.calls(), 1);
    }

    #[test]
    fn max_attempts_must_be_at_least_one() {
        let r = Resolver::new(&["a"]);
        let built = NcpFailoverConnector::with_max_attempts(
            || r.next(),
            |h: &str, _p| Ok(h.to_string()),
            shaped,
            0,
        );
        assert!(matches!(
            built.err(),
            Some(FailoverConfigError::MaxAttemptsTooSmall(0))
        ));

        assert!(NcpFailoverConnector::with_max_attempts(
            || r.next(),
            |h: &str, _p| Ok(h.to_string()),
            shaped,
            1,
        )
        .is_ok());
    }

    #[test]
    fn a_resolution_failure_surfaces_as_resolve() {
        let c = NcpFailoverConnector::new(
            || Err::<(String, u16), _>(TestError::Socket("no registry")),
            |h: &str, _p| Ok(h.to_string()),
            shaped,
        )
        .unwrap();
        assert!(matches!(c.connect(), Err(FailoverError::Resolve(_))));
    }

    #[test]
    fn nid_mismatch_matcher_uses_the_wire_constant() {
        assert!(is_nid_mismatch("NCP-NID-MISMATCH"));
        assert!(is_nid_mismatch(NID_MISMATCH));
        assert!(!is_nid_mismatch("NCP-FRAME-FLAGS-INVALID"));
    }
}
