// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use crate::frames::FrameType;

pub struct FrameRegistry {
    registered: HashSet<u8>,
}

impl FrameRegistry {
    pub fn new() -> Self {
        FrameRegistry { registered: HashSet::new() }
    }

    pub fn register(&mut self, ft: FrameType) {
        self.registered.insert(ft.as_u8());
    }

    pub fn is_registered(&self, ft: FrameType) -> bool {
        self.registered.contains(&ft.as_u8())
    }

    /// NCP only
    pub fn create_default() -> Self {
        let mut r = Self::new();
        r.register(FrameType::Anchor);
        r.register(FrameType::Diff);
        r.register(FrameType::Stream);
        r.register(FrameType::Caps);
        r.register(FrameType::Error);
        r
    }

    /// All five protocols
    pub fn create_full() -> Self {
        let mut r = Self::create_default();
        // NWP
        r.register(FrameType::Query);
        r.register(FrameType::Action);
        // NIP
        r.register(FrameType::Ident);
        r.register(FrameType::Trust);
        r.register(FrameType::Revoke);
        // NDP
        r.register(FrameType::Announce);
        r.register(FrameType::Resolve);
        r.register(FrameType::Graph);
        // NOP
        r.register(FrameType::Task);
        r.register(FrameType::Delegate);
        r.register(FrameType::Sync);
        r.register(FrameType::AlignStream);
        r
    }
}

impl Default for FrameRegistry {
    fn default() -> Self {
        Self::new()
    }
}
