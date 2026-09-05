// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub mod alpha19;

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
    #[allow(clippy::too_many_arguments)]
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
            profile_version: if profile == NODE_L2 { "0.7" } else { "0.1" }.to_string(),
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
            };
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
        if result.result == "na"
            && matches!(result.id.as_str(), "TC-N2-AaaS-06" | "TC-N2-AaaS-07")
            && result
                .message
                .as_deref()
                .is_none_or(|message| message.trim().is_empty())
        {
            return NpsConformanceValidation {
                valid: false,
                message: format!(
                    "Case '{}' requires a non-empty message for a SHOULD exception.",
                    result.id
                ),
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
    let expected_version = if manifest.profile == NODE_L2 {
        "0.7"
    } else {
        "0.1"
    };
    if manifest.profile_version != expected_version {
        return NpsConformanceValidation {
            valid: false,
            message: format!(
                "Profile '{}' requires manifest version '{}'.",
                manifest.profile, expected_version
            ),
        };
    }
    let expected_summary = NpsConformanceSummary {
        pass: manifest.cases.iter().filter(|r| r.result == "pass").count(),
        fail: manifest.cases.iter().filter(|r| r.result == "fail").count(),
        skip: manifest.cases.iter().filter(|r| r.result == "skip").count(),
        na: manifest.cases.iter().filter(|r| r.result == "na").count(),
    };
    if manifest.summary != expected_summary {
        return NpsConformanceValidation {
            valid: false,
            message: "Conformance manifest summary does not match case results.".to_string(),
        };
    }
    if manifest.profile == NODE_L2 {
        let results: std::collections::HashMap<&str, &str> = manifest
            .cases
            .iter()
            .map(|result| (result.id.as_str(), result.result.as_str()))
            .collect();
        let families: &[&[&str]] = &[
            &[
                "TC-N2-Tls-01",
                "TC-N2-Tls-02",
                "TC-N2-Tls-03",
                "TC-N2-Tls-04",
            ],
            &[
                "TC-N2-BridgeIn-01",
                "TC-N2-BridgeIn-02",
                "TC-N2-BridgeIn-03",
                "TC-N2-BridgeIn-04",
                "TC-N2-BridgeIn-05",
                "TC-N2-BridgeIn-06",
            ],
            &[
                "TC-N2-HA-01",
                "TC-N2-HA-02",
                "TC-N2-HA-03",
                "TC-N2-HA-04",
                "TC-N2-HA-05",
                "TC-N2-HA-06",
            ],
            &["TC-N2-HA-07", "TC-N2-HA-08"],
        ];
        for family in families {
            let expected = results[family[0]];
            if !matches!(expected, "pass" | "na") || family.iter().any(|id| results[id] != expected)
            {
                return NpsConformanceValidation {
                    valid: false,
                    message: format!("L2 case family '{}' must be all pass or all na.", family[0]),
                };
            }
        }
        if (results["TC-N2-HA-01"] == "na") == (results["TC-N2-HA-09"] == "na") {
            return NpsConformanceValidation {
                valid: false,
                message: "L2 multi-Anchor HA and single-Anchor compatibility cases must have opposite applicability.".to_string(),
            };
        }
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
        "TC-N2-AaaS-01",
        NODE_L2,
        "L2-01",
        "Internal work uses NOP TaskFrame",
        false,
    ),
    c(
        "TC-N2-AaaS-02",
        NODE_L2,
        "L2-02",
        "OpenTelemetry TaskFrame context injection",
        false,
    ),
    c(
        "TC-N2-AaaS-03",
        NODE_L2,
        "L2-03",
        "CGN-Estimate budget and token_est response",
        false,
    ),
    c(
        "TC-N2-AaaS-04",
        NODE_L2,
        "L2-04",
        "NOP preflight gates worker dispatch",
        false,
    ),
    c(
        "TC-N2-AaaS-05",
        NODE_L2,
        "L2-05",
        "NOP retry and timeout semantics",
        false,
    ),
    c(
        "TC-N2-AaaS-06",
        NODE_L2,
        "L2-06",
        "Asynchronous Action lifecycle",
        true,
    ),
    c(
        "TC-N2-AaaS-07",
        NODE_L2,
        "L2-07",
        "AlignStream CGN back-pressure",
        true,
    ),
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
        true,
    ),
    c(
        "TC-N2-Tls-02",
        NODE_L2,
        "NPS-RFC-0006",
        "Mutual TLS required",
        true,
    ),
    c(
        "TC-N2-Tls-03",
        NODE_L2,
        "NPS-RFC-0006",
        "Client cert trust anchor and NID binding",
        true,
    ),
    c(
        "TC-N2-Tls-04",
        NODE_L2,
        "NPS-RFC-0006",
        "IdentFrame/certificate NID mismatch",
        true,
    ),
    c(
        "TC-N2-BridgeIn-01",
        NODE_L2,
        "NPS-CR-0010",
        "MCP inbound required method set",
        true,
    ),
    c(
        "TC-N2-BridgeIn-02",
        NODE_L2,
        "NPS-CR-0010",
        "gRPC inbound round-trip",
        true,
    ),
    c(
        "TC-N2-BridgeIn-03",
        NODE_L2,
        "NPS-CR-0010",
        "A2A inbound round-trip",
        true,
    ),
    c(
        "TC-N2-BridgeIn-04",
        NODE_L2,
        "NPS-CR-0010",
        "Bare action resolution and ambiguity rejection",
        true,
    ),
    c(
        "TC-N2-BridgeIn-05",
        NODE_L2,
        "NPS-CR-0010",
        "Foreign-protocol error mapping",
        true,
    ),
    c(
        "TC-N2-BridgeIn-06",
        NODE_L2,
        "NPS-CR-0010",
        "Undeclared protocol or direction refusal",
        true,
    ),
    c(
        "TC-N2-HA-01",
        NODE_L2,
        "NPS-CR-0009",
        "cluster_epoch on topology read surfaces",
        true,
    ),
    c(
        "TC-N2-HA-02",
        NODE_L2,
        "NPS-CR-0009",
        "Planned anchor_failover wire shape",
        true,
    ),
    c(
        "TC-N2-HA-03",
        NODE_L2,
        "NPS-CR-0009",
        "Active-loss failover is terminal",
        true,
    ),
    c(
        "TC-N2-HA-04",
        NODE_L2,
        "NPS-CR-0009",
        "Quorum-loss wire shape and read-only mode",
        true,
    ),
    c(
        "TC-N2-HA-05",
        NODE_L2,
        "NPS-CR-0009",
        "Standby rejects topology writes",
        true,
    ),
    c(
        "TC-N2-HA-06",
        NODE_L2,
        "NPS-CR-0009",
        "Superseded leader is epoch fenced",
        true,
    ),
    c(
        "TC-N2-HA-07",
        NODE_L2,
        "NPS-CR-0009",
        "Registry resolves highest cluster_epoch",
        true,
    ),
    c(
        "TC-N2-HA-08",
        NODE_L2,
        "NPS-CR-0009",
        "Equal-epoch split-brain rejection",
        true,
    ),
    c(
        "TC-N2-HA-09",
        NODE_L2,
        "NPS-CR-0009",
        "Single-Anchor epoch-one compatibility",
        true,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_expected_cases() {
        assert_eq!(NODE_L1_CASES.len(), 20);
        assert_eq!(NODE_L2_CASES.len(), 38);
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
            "1.0.0-alpha.18",
            results,
            "",
        );
        assert!(validate_manifest(&manifest).valid);
    }

    #[test]
    fn validator_enforces_l2_all_or_nothing_families() {
        let results = NODE_L2_CASES
            .iter()
            .map(|case| NpsConformanceCaseResult {
                id: case.id.to_string(),
                result: if case.id.starts_with("TC-N2-AaaS-")
                    || case.id.starts_with("TC-N2-Anchor")
                    || case.id == "TC-N2-HA-09"
                {
                    "pass"
                } else {
                    "na"
                }
                .to_string(),
                message: None,
            })
            .collect();
        let mut manifest = NpsConformanceManifest::create(
            NODE_L2,
            "single-anchor",
            "0.1.0",
            "urn:nps:node:example.test:anchor-1",
            "reference",
            "1.0.0-alpha.18",
            results,
            "",
        );
        assert_eq!(manifest.profile_version, "0.7");
        assert!(validate_manifest(&manifest).valid);

        manifest.cases[19].result = "pass".to_string();
        manifest.summary.pass += 1;
        manifest.summary.na -= 1;
        let validation = validate_manifest(&manifest);
        assert!(!validation.valid);
        assert!(validation.message.contains("must be all pass or all na"));

        manifest.cases[19].result = "na".to_string();
        let last = manifest.cases.len() - 1;
        manifest.cases[last].result = "na".to_string();
        manifest.summary.pass -= 2;
        manifest.summary.na += 2;
        let applicability = validate_manifest(&manifest);
        assert!(!applicability.valid);
        assert!(applicability.message.contains("opposite applicability"));
    }

    #[test]
    fn validator_requires_reason_for_aaas_should_exception() {
        let mut results: Vec<_> = NODE_L2_CASES
            .iter()
            .map(|case| NpsConformanceCaseResult {
                id: case.id.to_string(),
                result: if case.id.starts_with("TC-N2-AaaS-")
                    || case.id.starts_with("TC-N2-Anchor")
                    || case.id == "TC-N2-HA-09"
                {
                    "pass"
                } else {
                    "na"
                }
                .to_string(),
                message: None,
            })
            .collect();
        results[5].result = "na".to_string();
        let missing_reason = NpsConformanceManifest::create(
            NODE_L2,
            "service",
            "0.1.0",
            "urn:nps:node:example.test:anchor-1",
            "reference",
            "1.0.0-alpha.18",
            results.clone(),
            "",
        );
        assert!(validate_manifest(&missing_reason)
            .message
            .contains("requires a non-empty message"));

        results[5].message = Some("Synchronous-only deployment".to_string());
        let reasoned = NpsConformanceManifest::create(
            NODE_L2,
            "service",
            "0.1.0",
            "urn:nps:node:example.test:anchor-1",
            "reference",
            "1.0.0-alpha.18",
            results,
            "",
        );
        assert!(validate_manifest(&reasoned).valid);
    }
}
