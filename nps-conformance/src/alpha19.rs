// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Side-effect-free alpha.19 decisions shared by runtimes and conformance runners.

use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

pub type Output = Map<String, Value>;
fn object(value: Value) -> Output {
    value.as_object().unwrap().clone()
}
fn obj<'a>(i: &'a Output, key: &str) -> &'a Output {
    i.get(key).and_then(Value::as_object).unwrap()
}
fn arr<'a>(i: &'a Output, key: &str) -> &'a Vec<Value> {
    i.get(key).and_then(Value::as_array).unwrap()
}
fn int(i: &Output, key: &str) -> i64 {
    i.get(key).and_then(Value::as_i64).unwrap_or(0)
}
fn float(i: &Output, key: &str) -> f64 {
    i.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}
fn text<'a>(i: &'a Output, key: &str) -> &'a str {
    i.get(key).and_then(Value::as_str).unwrap_or("")
}
fn boolean(i: &Output, key: &str) -> bool {
    i.get(key).and_then(Value::as_bool).unwrap_or(false)
}
fn instant(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}
fn format(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap()
}
fn subset(want: &[Value], have: &[Value]) -> bool {
    want.iter().all(|v| have.contains(v))
}

pub fn ncp(i: &Output) -> Output {
    if i.contains_key("client_ping_ms") {
        let offers: Vec<_> = [int(i, "client_ping_ms"), int(i, "server_ping_ms")]
            .into_iter()
            .filter(|x| *x > 0)
            .collect();
        return if offers.is_empty() {
            object(json!({"keepalive_enabled":false,"effective_interval_ms":null}))
        } else {
            object(
                json!({"keepalive_enabled":true,"effective_interval_ms":offers.into_iter().min().unwrap().max(1000)}),
            )
        };
    }
    if i.contains_key("events") {
        let mut clock = int(i, "last_valid_inbound_ms");
        for event in arr(i, "events").iter().filter_map(Value::as_object) {
            if text(event, "event") == "valid_inbound_frame" {
                clock = int(event, "at_ms")
            }
        }
        return object(json!({"last_valid_inbound_ms":clock}));
    }
    if i.contains_key("queued_probe_count") {
        let due = int(i, "evaluate_at_ms") - int(i, "last_application_send_ms")
            >= int(i, "effective_interval_ms");
        return if due && int(i, "queued_probe_count") == 0 {
            object(json!({"enqueue":{"frame":"0x07","payload_length":0},"queued_probe_count":1}))
        } else {
            object(json!({"queued_probe_count":int(i,"queued_probe_count")}))
        };
    }
    if i.contains_key("active_streams") {
        return if int(i, "evaluate_at_ms")
            >= int(i, "last_valid_inbound_ms") + 3 * int(i, "effective_interval_ms")
        {
            object(
                json!({"state":"closing","error":"NCP-KEEPALIVE-TIMEOUT","error_count":1,"cancelled_streams":int(i,"active_streams"),"close_by_ms":int(i,"evaluate_at_ms")+500,"allow_later_application_frames":false}),
            )
        } else {
            object(json!({"state":"open"}))
        };
    }
    if i.contains_key("payload_length") {
        return if int(i, "payload_length") == 0 {
            object(json!({"accepted":true,"last_valid_inbound_ms":int(i,"received_at_ms")}))
        } else {
            object(
                json!({"accepted":false,"error":"NCP-FRAME-PAYLOAD-TOO-LARGE","last_valid_inbound_ms":int(i,"last_valid_inbound_ms")}),
            )
        };
    }
    if i.contains_key("early_data") {
        return if text(i, "carrier") == "quic" && !boolean(i, "handshake_confirmed") {
            object(
                json!({"accepted":false,"error":"NCP-EARLY-DATA-REJECTED","retry_after_confirmation":true}),
            )
        } else {
            object(json!({"accepted":true}))
        };
    }
    if i.contains_key("bound_nid") {
        if !boolean(i, "handshake_confirmed") || text(i, "bound_nid") != text(i, "migrated_nid") {
            return object(
                json!({"migration_allowed":false,"session_preserved":false,"error":"NCP-NID-MISMATCH"}),
            );
        }
        let send = int(i, "carrier_credit_bytes") > 0 && int(i, "ncp_window_cgn") > 0;
        return if send {
            object(json!({"migration_allowed":true,"session_preserved":true,"send_allowed":true}))
        } else {
            object(
                json!({"migration_allowed":true,"session_preserved":true,"send_allowed":false,"reason":if int(i,"ncp_window_cgn")<=0{"ncp_window_exhausted"}else{"carrier_credit_exhausted"}}),
            )
        };
    }
    panic!("unknown NCP input")
}

fn sla(s: &Output, prefix: &str) -> (Output, Vec<Value>) {
    let mut o = Output::new();
    let mut d = vec![];
    if s.contains_key("p95_latency_ms") {
        let n = int(s, "p95_latency_ms");
        if n > 0 {
            o.insert("p95_latency_ms".into(), json!(n));
        } else {
            d.push(json!(format!("{prefix}p95_latency_ms")));
        }
    }
    if s.contains_key("availability") {
        let raw = text(s, "availability");
        let n: f64 = raw.parse().unwrap_or(0.0);
        if n > 0.0 && n <= 1.0 {
            o.insert("availability".into(), json!(raw));
        } else {
            d.push(json!(format!("{prefix}availability")));
        }
    }
    if s.contains_key("sla_tier") {
        let tier = text(s, "sla_tier");
        let rank = match tier {
            "basic" => Some(0),
            "standard" => Some(1),
            "premium" => Some(2),
            _ => None,
        };
        if let Some(r) = rank {
            o.insert("sla_tier".into(), json!(tier));
            o.insert("sla_tier_rank".into(), json!(r));
        } else {
            o.insert("sla_tier_raw".into(), json!(tier));
            o.insert("sla_tier_rank".into(), Value::Null);
        }
    }
    (o, d)
}
pub fn nwp_metadata(i: &Output) -> Output {
    if i.contains_key("stability") {
        if i["stability"].is_null() {
            return object(json!({"normalized":"stable","diagnostics":[]}));
        }
        let v = text(i, "stability");
        return if matches!(v, "experimental" | "stable" | "deprecated") {
            object(json!({"raw":v,"normalized":v,"rank_as_stable":v=="stable"}))
        } else {
            object(json!({"raw":v,"normalized":"experimental","rank_as_stable":false}))
        };
    }
    if i.contains_key("sla") {
        let (n, d) = sla(obj(i, "sla"), "");
        return object(json!({"manifest_valid":true,"normalized_sla":n,"diagnostics":d}));
    }
    if i.contains_key("billing") {
        let b = obj(i, "billing");
        let mut profile = text(b, "metering_profile");
        if !matches!(profile, "free" | "metered") {
            profile = "metered"
        }
        let mut n = object(json!({"metering_profile":profile}));
        let mut d = vec![];
        if profile == "free" {
            for k in ["billing_unit", "price_hint", "currency"] {
                if b.contains_key(k) {
                    d.push(json!(k))
                }
            }
        } else {
            let unit = text(b, "billing_unit");
            if unit.is_empty() {
                d.push(json!("billing_unit"))
            } else {
                n.insert("billing_unit".into(), json!(unit));
            }
            if b.contains_key("price_hint") {
                let price = text(b, "price_hint");
                let valid = price.len() > 4
                    && price.as_bytes()[..3].iter().all(u8::is_ascii_uppercase)
                    && price.as_bytes()[3] == b' '
                    && price[4..].parse::<f64>().is_ok();
                if valid {
                    if b.contains_key("currency") && text(b, "currency") != &price[..3] {
                        d.push(json!("currency"))
                    } else {
                        n.insert("price_hint".into(), json!(price));
                        if b.contains_key("currency") {
                            n.insert("currency".into(), json!(text(b, "currency")));
                        }
                    }
                } else {
                    d.push(json!("price_hint"));
                }
            }
        }
        return object(json!({"normalized_billing":n,"diagnostics":d}));
    }
    if i.contains_key("top_level") {
        let (mut base, _) = sla(obj(obj(i, "top_level"), "sla"), "");
        let (over, d) = sla(obj(obj(i, "action"), "sla"), "action.sla.");
        base.extend(over);
        return object(json!({"effective_sla":base,"diagnostics":d}));
    }
    panic!("unknown metadata input")
}

pub fn nwp_subscription(i: &Output) -> Output {
    if i.contains_key("policy") {
        let p = obj(i, "policy");
        let r = obj(i, "request");
        let (def, max, renew) = (
            int(p, "default_lease_seconds"),
            int(p, "max_lease_seconds"),
            int(p, "renew_before_seconds"),
        );
        if def <= 0 || max <= 0 || def > max || renew >= max {
            return object(
                json!({"accepted":false,"error":"NWP-SUBSCRIBE-LEASE-INVALID","state_mutated":false}),
            );
        }
        let mut lease = if r.contains_key("lease_seconds") {
            int(r, "lease_seconds")
        } else {
            def
        };
        if lease <= 0 {
            return object(
                json!({"accepted":false,"error":"NWP-SUBSCRIBE-LEASE-INVALID","state_mutated":false}),
            );
        }
        lease = lease.min(max);
        let expires = format(instant(text(i, "accepted_at")) + Duration::seconds(lease));
        return if r.contains_key("lease_seconds") {
            object(json!({"lease_seconds":lease,"expires_at":expires}))
        } else {
            object(json!({"lease_seconds":lease,"expires_at":expires,"status":"open"}))
        };
    }
    if i.contains_key("owner_nid") {
        return if text(i, "owner_nid") == text(i, "caller_nid") {
            object(json!({"accepted":true}))
        } else {
            object(
                json!({"accepted":false,"error":"NWP-AUTH-NID-SCOPE-VIOLATION","state_disclosed":false}),
            )
        };
    }
    if i.contains_key("prior_seq") {
        return object(
            json!({"expires_at":format(instant(text(i,"accepted_at"))+Duration::seconds(int(i,"lease_seconds"))),"seq":int(i,"prior_seq"),"cursor":text(i,"prior_cursor")}),
        );
    }
    if i.contains_key("expires_at") {
        return if instant(text(i, "now")) >= instant(text(i, "expires_at")) {
            object(
                json!({"accepted":false,"status":"closed","error":"NWP-SUBSCRIBE-LEASE-EXPIRED","terminal_event_count":1}),
            )
        } else {
            object(json!({"accepted":true}))
        };
    }
    if matches!(text(i, "operation"), "renew" | "close")
        && ["anchor_ref", "filter", "type"]
            .iter()
            .any(|k| i.contains_key(*k))
    {
        return object(
            json!({"accepted":false,"error":"NWP-SUBSCRIBE-LEASE-INVALID","state_mutated":false}),
        );
    }
    panic!("unknown subscription input")
}

pub fn nip_renewal(i: &Output) -> Output {
    if text(i, "profile") == "standard" {
        let open = instant(text(i, "not_after")) - instant(text(i, "now")) <= Duration::days(7);
        return object(
            json!({"renewal_open":open,"error":if open{Value::Null}else{json!("NIP-CA-RENEWAL-TOO-EARLY")}}),
        );
    }
    if text(i, "profile") == "short-lived-edge" {
        let w = int(i, "original_validity_seconds") / 4;
        return object(json!({"renewal_open":int(i,"remaining_seconds")<=w,"window_seconds":w}));
    }
    if i.contains_key("current") {
        let c = obj(i, "current");
        let r = obj(i, "requested");
        let allowed = subset(arr(r, "capabilities"), arr(c, "capabilities"))
            && subset(arr(r, "scope"), arr(c, "scope"));
        return if allowed {
            object(json!({"issued":true}))
        } else {
            object(json!({"issued":false,"error":"NIP-CA-SCOPE-EXPANSION-DENIED"}))
        };
    }
    if i.contains_key("recorded") {
        let r = obj(i, "recorded");
        return if boolean(r, "committed")
            && text(r, "canonical_digest") == text(i, "canonical_digest")
        {
            object(json!({"serial":text(r,"serial"),"new_issue_count":0}))
        } else {
            object(json!({"error":"NIP-CA-SERIAL-DUPLICATE","new_issue_count":0}))
        };
    }
    if i.contains_key("old_ticket_not_after") {
        return object(json!({"old_ticket_not_after":text(i,"old_ticket_not_after")}));
    }
    panic!("unknown renewal input")
}
pub fn nip_revocation(i: &Output) -> Output {
    if i.contains_key("cached") {
        let c = obj(i, "cached");
        let n = obj(i, "incoming");
        let replace = boolean(n, "signature_valid")
            && instant(text(n, "this_update")) > instant(text(c, "this_update"));
        return object(
            json!({"cache_replaced":replace,"effective_outcome":text(if replace{n}else{c},"outcome")}),
        );
    }
    let mut consulted = vec![];
    let mut diagnostics = vec![];
    for raw in i
        .get("sources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let s = raw.as_object().unwrap();
        let name = text(s, "source");
        let outcome = text(s, "outcome");
        consulted.push(json!(name));
        if outcome == "unknown" {
            return object(json!({"valid":false,"error":"NIP-OCSP-UNKNOWN"}));
        }
        if i.contains_key("now")
            && s.contains_key("next_update")
            && instant(text(i, "now")) >= instant(text(s, "next_update"))
        {
            diagnostics.push(json!(format!("{name}_stale")));
            continue;
        }
        if outcome == "revoked" {
            return object(json!({"valid":false,"error":"NIP-CERT-REVOKED"}));
        }
        if outcome == "good" {
            return if diagnostics.is_empty() {
                object(json!({"valid":true,"consulted_sources":consulted}))
            } else {
                object(
                    json!({"valid":true,"consulted_sources":consulted,"diagnostics":diagnostics}),
                )
            };
        }
    }
    if text(i, "revocation_mode") == "required" {
        object(json!({"valid":false,"error":"NIP-REVOCATION-STATE-STALE"}))
    } else {
        object(json!({"valid":true,"consulted_sources":consulted}))
    }
}
pub fn nip_advisory(i: &Output) -> Output {
    let ident = obj(i, "ident");
    let ext = obj(i, "certificate_extensions");
    let mut f = vec![];
    if text(ident, "assurance_level") != text(ext, "assurance_level") {
        f.push(json!({"field":"assurance_level","error":"NIP-ASSURANCE-MISMATCH"}))
    }
    if !subset(
        arr(ident, "capabilities"),
        ext.get("capabilities")
            .and_then(Value::as_array)
            .unwrap_or(&vec![]),
    ) {
        f.push(json!({"field":"capabilities","error":"NIP-CERT-CAPABILITIES-EXCEEDED"}))
    }
    if !subset(
        arr(ident, "node_roles"),
        ext.get("node_roles")
            .and_then(Value::as_array)
            .unwrap_or(&vec![]),
    ) {
        f.push(json!({"field":"node_roles","error":"NIP-CERT-NODE-ROLES-MISMATCH"}))
    }
    if ident.get("ocsp_staple").is_none_or(Value::is_null) {
        f.push(json!({"field":"ocsp_staple","error":"NIP-OCSP-STAPLE-EXPIRED"}))
    }
    f.sort_by_key(|x| x["field"].as_str().unwrap().to_owned());
    object(
        json!({"accepted_current_request":!boolean(i,"phase3_enforcement"),"findings":f,"state_mutated":false}),
    )
}

pub fn ndp(i: &Output) -> Output {
    if i.contains_key("commit") {
        return if text(i, "commit") == "success" {
            object(
                json!({"acknowledged":true,"served_seq":int(i,"incoming_seq"),"persisted_seq":int(i,"incoming_seq")}),
            )
        } else {
            object(
                json!({"acknowledged":false,"served_seq":int(i,"persisted_seq"),"persisted_seq":int(i,"persisted_seq"),"error":"NDP-STATE-UNAVAILABLE"}),
            )
        };
    }
    if i.contains_key("now") {
        let r = obj(i, "record");
        return object(
            json!({"live_entry":instant(text(r,"fresh_until"))>instant(text(i,"now")),"highest_seq":int(r,"highest_seq"),"ready":true}),
        );
    }
    if i.contains_key("restored_highest_seq") {
        return if int(i, "incoming_seq") < int(i, "restored_highest_seq") {
            object(
                json!({"accepted":false,"highest_seq":int(i,"restored_highest_seq"),"error":"NDP-GRAPH-SEQ-ROLLBACK"}),
            )
        } else {
            object(json!({"accepted":true,"highest_seq":int(i,"incoming_seq")}))
        };
    }
    if i.contains_key("owners") {
        let live: Vec<_> = arr(i, "owners")
            .iter()
            .filter_map(Value::as_object)
            .filter(|x| boolean(x, "live"))
            .collect();
        let top = live.iter().map(|x| int(x, "epoch")).max().unwrap();
        let mut leaders: Vec<_> = live
            .iter()
            .filter(|x| int(x, "epoch") == top)
            .map(|x| text(x, "nid"))
            .collect();
        leaders.sort();
        return if leaders.len() == 1 {
            object(json!({"resolved_nid":leaders[0]}))
        } else {
            object(json!({"resolved_nid":null,"error":"NDP-CLUSTER-SPLIT"}))
        };
    }
    if i.contains_key("snapshot_validation") {
        return if text(i, "snapshot_validation") == "valid" {
            object(json!({"ready":true,"started_empty":false}))
        } else {
            object(json!({"ready":false,"started_empty":false,"error":"NDP-STATE-CORRUPT"}))
        };
    }
    if i.contains_key("profiles") {
        return object(
            json!({"recovery":arr(i,"profiles").iter().map(|x|if x.as_str()==Some("local-dev"){"volatile"}else{"durable"}).collect::<Vec<_>>()}),
        );
    }
    if i.contains_key("revoked_origin") {
        let r = obj(i, "record");
        return object(
            json!({"live":boolean(r,"live")&&text(r,"origin")!=text(i,"revoked_origin"),"highest_seq":int(r,"highest_seq")}),
        );
    }
    panic!("unknown NDP input")
}

pub fn nop(i: &Output) -> Output {
    if i.contains_key("recorded") && text(obj(i, "recorded"), "digest") == text(i, "digest") {
        let r = obj(i, "recorded");
        return object(
            json!({"state":text(r,"state"),"dispatch_count":int(r,"dispatch_count"),"replayed":true}),
        );
    }
    if i.contains_key("recorded_digest") {
        return if text(i, "digest") != text(i, "recorded_digest") {
            object(json!({"accepted":false,"error":"NOP-REPLAY-CONFLICT","record_mutated":false}))
        } else {
            object(json!({"accepted":true}))
        };
    }
    if i.contains_key("incoming") {
        let n = obj(i, "incoming");
        let found = arr(i, "records")
            .iter()
            .filter_map(Value::as_object)
            .any(|r| {
                text(r, "caller_nid") == text(n, "caller_nid")
                    && text(r, "task_id") == text(n, "task_id")
            });
        return object(json!({"new_key":!found,"accepted":!found}));
    }
    if i.contains_key("terminal_commit_ms") {
        return if int(i, "query_at_ms")
            >= int(i, "terminal_commit_ms") + 1000 * int(i, "result_ttl_seconds")
        {
            object(json!({"result":null,"error":"NOP-TASK-RESULT-EXPIRED"}))
        } else {
            object(json!({"result":"retained"}))
        };
    }
    if i.contains_key("result_expired_at_ms") {
        let retained = int(i, "duplicate_at_ms")
            < int(i, "result_expired_at_ms") + 1000 * int(i, "replay_tombstone_seconds");
        return if retained {
            object(
                json!({"dispatch":false,"error":"NOP-TASK-RESULT-EXPIRED","tombstone_retained":true}),
            )
        } else {
            object(json!({"dispatch":true,"tombstone_retained":false}))
        };
    }
    if i.contains_key("capacity") {
        let records = arr(i, "records");
        let safe: Vec<_> = records
            .iter()
            .filter_map(Value::as_object)
            .filter(|r| text(r, "state") != "running")
            .collect();
        return if records.len() as i64 >= int(i, "capacity") && safe.is_empty() {
            object(json!({"accepted":false,"evicted":[],"error":"NOP-REPLAY-LIMIT"}))
        } else {
            object(
                json!({"accepted":true,"evicted":safe.first().map(|r|vec![json!(text(r,"key"))]).unwrap_or_default()}),
            )
        };
    }
    if i.contains_key("committed") {
        return object(
            json!({"state":text(obj(i,"committed"),"state"),"late_event":"audit_only","ttl_extended":false}),
        );
    }
    if i.contains_key("min_required") {
        let mut results: Vec<_> = arr(i, "results")
            .iter()
            .filter_map(Value::as_object)
            .collect();
        if results
            .iter()
            .any(|r| !r.contains_key("score") || !float(r, "score").is_finite())
        {
            return object(json!({"error":"NOP-AGGREGATION-INVALID"}));
        }
        results.sort_by(|a, b| {
            float(b, "score")
                .partial_cmp(&float(a, "score"))
                .unwrap_or(Ordering::Equal)
                .then_with(|| text(a, "node_id").cmp(text(b, "node_id")))
        });
        return object(
            json!({"selected_node_ids":results.into_iter().take(int(i,"min_required") as usize).map(|r|text(r,"node_id")).collect::<Vec<_>>()}),
        );
    }
    if i.contains_key("topology_order") {
        let by: std::collections::HashMap<_, _> = arr(i, "results")
            .iter()
            .filter_map(Value::as_object)
            .map(|r| (text(r, "node_id"), r))
            .collect();
        let mut agg = Output::new();
        for id in arr(i, "topology_order").iter().filter_map(Value::as_str) {
            let Some(r) = by.get(id) else { continue };
            if text(r, "state") != "completed" {
                continue;
            }
            for (k, v) in obj(r, "value") {
                if let (Some(Value::Array(left)), Value::Array(right)) = (agg.get_mut(k), v) {
                    left.extend(right.clone())
                } else {
                    agg.insert(k.clone(), v.clone());
                }
            }
        }
        return object(json!({"aggregated":agg,"inputs_mutated":false}));
    }
    panic!("unknown NOP input")
}
