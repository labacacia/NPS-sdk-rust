// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug, Clone)]
pub enum NpsError {
    Frame(String),
    Codec(String),
    AnchorNotFound(String),
    AnchorPoison(String),
    Identity(String),
    Io(String),
}

impl fmt::Display for NpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NpsError::Frame(m)          => write!(f, "NPS frame error: {m}"),
            NpsError::Codec(m)          => write!(f, "NPS codec error: {m}"),
            NpsError::AnchorNotFound(m) => write!(f, "NPS anchor not found: {m}"),
            NpsError::AnchorPoison(m)   => write!(f, "NPS anchor poison: {m}"),
            NpsError::Identity(m)       => write!(f, "NPS identity error: {m}"),
            NpsError::Io(m)             => write!(f, "NPS IO error: {m}"),
        }
    }
}

impl std::error::Error for NpsError {}

pub type NpsResult<T> = Result<T, NpsError>;
