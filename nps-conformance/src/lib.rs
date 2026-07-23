// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub const NODE_L1: &str = "NPS-Node-L1";
pub const NODE_L2: &str = "NPS-Node-L2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpsConformanceCase {
    pub id: &'static str,
    pub profile: &'static str,
    pub requirement: &'static str,
    pub title: &'static str,
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpsConformanceCaseResult {
    pub id: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpsConformanceActor {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpsConformanceRun {
    pub date: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpsConformanceSummary {
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub na: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpsConformanceManifest {
    pub profile: String,
    pub profile_version: String,
    pub iut: NpsConformanceActor,
    pub peer: NpsConformanceActor,
    pub run: NpsConformanceRun,
    pub cases: Vec<NpsConformanceCaseResult>,
    pub summary: NpsConformanceSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpsConformanceValidation {
    pub valid: bool,
    pub message: String,
}

impl NpsConformanceManifest {
    pub fn create(
        profile: impl Into<String>,
        iut_name: impl Into<String>,
        iut_version: impl Into<String>,
        iut_nid: impl Into<String>,
        peer_name: impl Into<String>,
        peer_version: impl Into<String>,
        results: Vec<NpsConformanceCaseResult>,
        environment: impl Into<String>,
    ) -> Self {
        let profile = profile.into();
        let environment = {
            let v = environment.into();
            if v.is_empty() {
                "unspecified".to_string()
            } else {
                v
            }
        };
        Self {
            profile_version: if profile == NODE_L2 { "0.3" } else { "0.1" }.to_string(),
            iut: NpsConformanceActor {
                name: iut_name.into(),
                version: iut_version.into(),
                nid: Some(iut_nid.into()),
            },
            peer: NpsConformanceActor {
                name: peer_name.into(),
                version: peer_version.into(),
                nid: None,
            },
            run: NpsConformanceRun {
                date: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
                environment,
            },
            summary: NpsConformanceSummary {
                pass: results.iter().filter(|r| r.result == "pass").count(),
                fail: results.iter().filter(|r| r.result == "fail").count(),
                skip: results.iter().filter(|r| r.result == "skip").count(),
                na: results.iter().filter(|r| r.result == "na").count(),
            },
            profile,
            cases: results,
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

pub fn catalog_for_profile(profile: &str) -> Result<&'static [NpsConformanceCase], String> {
    match profile {
        NODE_L1 => Ok(NODE_L1_CASES),
        NODE_L2 => Ok(NODE_L2_CASES),
        _ => Err(format!("Unknown NPS conformance profile: {profile}")),
    }
}

pub fn validate_manifest(manifest: &NpsConformanceManifest) -> NpsConformanceValidation {
    let catalog = match catalog_for_profile(&manifest.profile) {
        Ok(c) => c,
        Err(e) => {
            return NpsConformanceValidation {
                valid: false,
                message: e,
            }
        }
    };
    let known: std::collections::HashMap<&str, &NpsConformanceCase> =
        catalog.iter().map(|c| (c.id, c)).collect();
    let mut seen = std::collections::HashSet::new();
    for result in &manifest.cases {
        let Some(case) = known.get(result.id.as_str()) else {
            return NpsConformanceValidation {
                valid: false,
                message: format!("Unknown conformance case id '{}'.", result.id),
            };
        };
        if !seen.insert(result.id.as_str()) {
            return NpsConformanceValidation {
                valid: false,
                message: format!("Duplicate conformance case id '{}'.", result.id),
            };
        }
        if !matches!(result.result.as_str(), "pass" | "fail" | "skip" | "na") {
            return NpsConformanceValidation {
                valid: false,
                message: format!(
                    "Case '{}' has invalid result '{}'.",
                    result.id, result.result
                ),
            };
        }
        if result.result == "na" && !case.optional {
            return NpsConformanceValidation {
                valid: false,
                message: format!("Case '{}' is required and cannot be marked na.", result.id),
            };
        }
    }
    let missing: Vec<_> = catalog
        .iter()
        .filter(|c| !seen.contains(c.id))
        .map(|c| c.id)
        .collect();
    if !missing.is_empty() {
        return NpsConformanceValidation {
            valid: false,
            message: format!("Missing conformance case results: {}.", missing.join(", ")),
        };
    }
    if manifest
        .cases
        .iter()
        .any(|c| c.result == "fail" || c.result == "skip")
    {
        return NpsConformanceValidation {
            valid: false,
            message: "Conformance manifest contains fail or skip results.".to_string(),
        };
    }
    NpsConformanceValidation {
        valid: true,
        message: "Conformance manifest is valid.".to_string(),
    }
}

const fn c(
    id: &'static str,
    profile: &'static str,
    requirement: &'static str,
    title: &'static str,
    optional: bool,
) -> NpsConformanceCase {
    NpsConformanceCase {
        id,
        profile,
        requirement,
        title,
        optional,
    }
}

pub const NODE_L1_CASES: &[NpsConformanceCase] = &[
    c(
        "TC-N1-NCP-01",
        NODE_L1,
        "N1-NCP-01",
        "Tier-1 JSON frame round-trip",
        false,
    ),
    c(
        "TC-N1-NCP-02",
        NODE_L1,
        "N1-NCP-02",
        "Hello + Anchor handshake",
        false,
    ),
    c(
        "TC-N1-NCP-03",
        NODE_L1,
        "N1-NCP-03",
        "Loopback listener default",
        false,
    ),
    c(
        "TC-N1-NCP-04",
        NODE_L1,
        "N1-NCP-04",
        "Tier-2 negotiation hygiene",
        false,
    ),
    c(
        "TC-N1-NIP-01",
        NODE_L1,
        "N1-NIP-01",
        "Root keypair generation and permission",
        false,
    ),
    c(
        "TC-N1-NIP-02",
        NODE_L1,
        "N1-NIP-02",
        "IdentFrame sign and verify",
        false,
    ),
    c("TC-N1-NIP-03", NODE_L1, "N1-NIP-03", "NID format", false),
    c(
        "TC-N1-NIP-04",
        NODE_L1,
        "N1-NIP-04",
        "Sub-NID issuance",
        true,
    ),
    c(
        "TC-N1-NDP-01",
        NODE_L1,
        "N1-NDP-01",
        "AnnounceFrame carries activation_mode",
        false,
    ),
    c(
        "TC-N1-NDP-02",
        NODE_L1,
        "N1-NDP-02",
        "AnnounceFrame signature",
        false,
    ),
    c(
        "TC-N1-NDP-03",
        NODE_L1,
        "N1-NDP-03",
        "ResolveFrame response",
        false,
    ),
    c(
        "TC-N1-NDP-04",
        NODE_L1,
        "N1-NDP-04",
        "GraphFrame topology snapshot",
        true,
    ),
    c(
        "TC-N1-NWP-01",
        NODE_L1,
        "N1-NWP-01",
        "Inbox accepts ActionFrame",
        false,
    ),
    c(
        "TC-N1-NWP-02",
        NODE_L1,
        "N1-NWP-02",
        "Inbox persists across restart",
        false,
    ),
    c(
        "TC-N1-NWP-03",
        NODE_L1,
        "N1-NWP-03",
        "NWP pull serves inbox",
        false,
    ),
    c(
        "TC-N1-NWP-04",
        NODE_L1,
        "N1-NWP-04",
        "100 QPS baseline",
        false,
    ),
    c("TC-N1-NWP-05", NODE_L1, "N1-NWP-05", "Push path", true),
    c(
        "TC-N1-OBS-01",
        NODE_L1,
        "N1-OBS-01",
        "Frame log entry per direction",
        false,
    ),
    c(
        "TC-N1-OBS-02",
        NODE_L1,
        "N1-OBS-02",
        "Log entry fields",
        false,
    ),
    c(
        "TC-N1-OBS-03",
        NODE_L1,
        "N1-OBS-03",
        "Log destination flexibility",
        false,
    ),
];

pub const NODE_L2_CASES: &[NpsConformanceCase] = &[
    c(
        "TC-N2-AnchorTopo-01",
        NODE_L2,
        "L2-08",
        "Snapshot of a 3-member cluster",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-02",
        NODE_L2,
        "L2-08",
        "Version monotonicity across joins",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-03",
        NODE_L2,
        "L2-08",
        "Sub-Anchor member surfaces",
        false,
    ),
    c(
        "TC-N2-AnchorStream-01",
        NODE_L2,
        "L2-08",
        "member_joined on NDP Announce",
        false,
    ),
    c(
        "TC-N2-AnchorStream-02",
        NODE_L2,
        "L2-08",
        "member_left on NDP TTL expiry",
        false,
    ),
    c(
        "TC-N2-AnchorStream-03",
        NODE_L2,
        "L2-08",
        "Resume from topology.since_version",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-04",
        NODE_L2,
        "L2-08",
        "Unauthorized topology access",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-05",
        NODE_L2,
        "L2-08",
        "Depth cap exceeded",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-06",
        NODE_L2,
        "L2-08",
        "Unsupported topology scope",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-07",
        NODE_L2,
        "L2-08",
        "Unsupported topology filter",
        false,
    ),
    c(
        "TC-N2-AnchorTopo-08",
        NODE_L2,
        "L2-08",
        "Unsupported reserved topology type",
        false,
    ),
    c(
        "TC-N2-AnchorStream-04",
        NODE_L2,
        "L2-08",
        "resync_required when version is too old",
        false,
    ),
    c(
        "TC-N2-Tls-01",
        NODE_L2,
        "NPS-RFC-0006",
        "ALPN nps/1.0 negotiated over TLS 1.3",
        false,
    ),
    c(
        "TC-N2-Tls-02",
        NODE_L2,
        "NPS-RFC-0006",
        "Mutual TLS required",
        false,
    ),
    c(
        "TC-N2-Tls-03",
        NODE_L2,
        "NPS-RFC-0006",
        "Client cert trust anchor and NID binding",
        false,
    ),
    c(
        "TC-N2-Tls-04",
        NODE_L2,
        "NPS-RFC-0006",
        "IdentFrame/certificate NID mismatch",
        false,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_expected_cases() {
        assert_eq!(NODE_L1_CASES.len(), 20);
        assert_eq!(NODE_L2_CASES.len(), 16);
        assert_eq!(NODE_L1_CASES[0].id, "TC-N1-NCP-01");
    }

    #[test]
    fn validator_accepts_complete_l1_manifest() {
        let results = NODE_L1_CASES
            .iter()
            .map(|case| NpsConformanceCaseResult {
                id: case.id.to_string(),
                result: if case.optional { "na" } else { "pass" }.to_string(),
                message: None,
            })
            .collect();
        let manifest = NpsConformanceManifest::create(
            NODE_L1,
            "node",
            "0.1.0",
            "urn:nps:node:example.test:node-1",
            "reference",
            "1.0.0-alpha.16",
            results,
            "",
        );
        assert!(validate_manifest(&manifest).valid);
    }
}
