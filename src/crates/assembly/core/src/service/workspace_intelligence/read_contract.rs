//! Read-only projection of the workspace intelligence control record.
//!
//! The reader is a pure function over `serde_json::Value` and performs no IO.
//! In memory it never rewrites and never drops unknown keys, and every fault
//! fails closed with `enabled: None`, which derives `Off`, while the payload
//! stays equal to `ControlRecordRead::preserved`.
//!
//! `preserved` preserves JSON `Value` semantics, not bytes: this module does not
//! prove that stored bytes stay unchanged, and it does not exercise a full store
//! round trip. The authoritative record store in a later phase owns byte-level
//! round trips.
//!
//! The caller owns the accepted schema versions, because this phase must not
//! freeze a later field set or a version constant.

use serde_json::Value;

use super::mode::{
    derive_mode, CapabilityDelivery, DerivedMode, ModeFacts, WorkspaceModelRef,
    WorkspaceModelResolution,
};

/// Stable diagnostic code of a control-record read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlReadDiagnosticCode {
    /// The payload is not a JSON object.
    PayloadNotObject,
    /// `schema_version` is present but is not an unsigned 32-bit integer.
    SchemaVersionMalformed,
    /// `schema_version` is well formed but the caller does not accept it.
    SchemaVersionUnsupported,
    /// `enabled` is present but is not a boolean.
    EnabledMalformed,
    /// `model_ref` is present but is not a non-blank string.
    ModelRefMalformed,
}

impl ControlReadDiagnosticCode {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PayloadNotObject => "payload_not_object",
            Self::SchemaVersionMalformed => "schema_version_malformed",
            Self::SchemaVersionUnsupported => "schema_version_unsupported",
            Self::EnabledMalformed => "enabled_malformed",
            Self::ModelRefMalformed => "model_ref_malformed",
        }
    }
}

/// One diagnosed fault, with a stable code and an English detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlReadDiagnostic {
    /// Stable diagnostic code.
    pub(crate) code: ControlReadDiagnosticCode,
    /// English detail naming the offending value or JSON type.
    pub(crate) detail: String,
}

/// Result of a read-only control-record projection.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ControlRecordRead {
    /// Switch value. `None` means absent or unreadable; both derive `Off`.
    pub(crate) enabled: Option<bool>,
    /// Configured workspace model reference, projected only when the switch is
    /// on. A workspace that does not reference a model keeps its raw value in
    /// `preserved`.
    pub(crate) model_ref: Option<WorkspaceModelRef>,
    /// Diagnosed faults in detection order. A missing switch is a documented
    /// default, not a fault, so it produces no diagnostic.
    pub(crate) diagnostics: Vec<ControlReadDiagnostic>,
    /// The original payload, preserved with JSON `Value` semantics: unknown keys
    /// and fields of an unrecognized schema version stay present and unrewritten
    /// in this in-memory projection, so `preserved == raw`.
    ///
    /// This is not byte-level preservation and proves nothing about stored bytes
    /// or a full store round trip; the authoritative record store in a later
    /// phase owns those.
    pub(crate) preserved: Value,
}

/// Reads the workspace intelligence control record.
///
/// `accepted_schema_versions` lists the schema versions this caller
/// understands. A record without the field is legacy and stays readable. A
/// record whose schema version is unreadable or unaccepted is not interpreted
/// field by field, because an unknown shape may define the same key
/// differently; it fails closed and is preserved.
pub(crate) fn read_control_record(
    raw: &Value,
    accepted_schema_versions: &[u32],
) -> ControlRecordRead {
    let mut diagnostics = Vec::new();

    if !raw.is_object() {
        diagnostics.push(ControlReadDiagnostic {
            code: ControlReadDiagnosticCode::PayloadNotObject,
            detail: format!("expected a JSON object, found {}", json_kind(raw)),
        });
        return fail_closed(raw, diagnostics);
    }

    if let Some(version) = raw.get("schema_version") {
        match version.as_u64().and_then(|value| u32::try_from(value).ok()) {
            Some(version) if accepted_schema_versions.contains(&version) => {}
            Some(version) => {
                diagnostics.push(ControlReadDiagnostic {
                    code: ControlReadDiagnosticCode::SchemaVersionUnsupported,
                    detail: format!("schema version {version} is not accepted"),
                });
                return fail_closed(raw, diagnostics);
            }
            None => {
                diagnostics.push(ControlReadDiagnostic {
                    code: ControlReadDiagnosticCode::SchemaVersionMalformed,
                    detail: format!(
                        "expected an unsigned 32-bit integer, found {}",
                        json_kind(version)
                    ),
                });
                return fail_closed(raw, diagnostics);
            }
        }
    }

    let enabled = match raw.get("enabled") {
        None => None,
        Some(Value::Bool(enabled)) => Some(*enabled),
        Some(other) => {
            diagnostics.push(ControlReadDiagnostic {
                code: ControlReadDiagnosticCode::EnabledMalformed,
                detail: format!("expected a boolean, found {}", json_kind(other)),
            });
            return fail_closed(raw, diagnostics);
        }
    };

    let model_ref = if matches!(enabled, Some(true)) {
        match raw.get("model_ref") {
            None => None,
            Some(Value::String(raw_ref)) => match WorkspaceModelRef::parse(raw_ref) {
                Some(model_ref) => Some(model_ref),
                None => {
                    diagnostics.push(ControlReadDiagnostic {
                        code: ControlReadDiagnosticCode::ModelRefMalformed,
                        detail: "model_ref is empty or blank".to_string(),
                    });
                    return fail_closed(raw, diagnostics);
                }
            },
            Some(other) => {
                diagnostics.push(ControlReadDiagnostic {
                    code: ControlReadDiagnosticCode::ModelRefMalformed,
                    detail: format!("expected a non-blank string, found {}", json_kind(other)),
                });
                return fail_closed(raw, diagnostics);
            }
        }
    } else {
        None
    };

    ControlRecordRead {
        enabled,
        model_ref,
        diagnostics,
        preserved: raw.clone(),
    }
}

/// Composes a derived mode from a control-record read.
///
/// Diagnostics stay with the caller; the derivation consumes only the switch
/// and the projected reference, so an unreadable record derives `Off`.
pub(crate) fn derive_from_read<F>(
    read: &ControlRecordRead,
    delivery: CapabilityDelivery,
    resolve: F,
) -> DerivedMode
where
    F: FnOnce(&WorkspaceModelRef) -> WorkspaceModelResolution,
{
    derive_mode(
        ModeFacts {
            enabled: read.enabled,
            model_ref: read.model_ref.clone(),
            delivery,
        },
        resolve,
    )
}

/// Fail-closed projection: no field of a record this reader cannot interpret is
/// projected, and the payload is preserved in memory with JSON `Value` semantics
/// (`preserved == raw`), which is not a byte-level guarantee.
fn fail_closed(raw: &Value, diagnostics: Vec<ControlReadDiagnostic>) -> ControlRecordRead {
    ControlRecordRead {
        enabled: None,
        model_ref: None,
        diagnostics,
        preserved: raw.clone(),
    }
}

/// JSON type name for diagnostics, so a detail never echoes a payload value.
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::workspace_intelligence::mode::{
        WorkspaceIntelligenceTier, WorkspaceModelState,
    };
    use serde_json::json;

    fn codes(read: &ControlRecordRead) -> Vec<ControlReadDiagnosticCode> {
        read.diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    fn projected_ref(read: &ControlRecordRead) -> Option<&str> {
        read.model_ref.as_ref().map(WorkspaceModelRef::as_str)
    }

    fn panic_resolver(_: &WorkspaceModelRef) -> WorkspaceModelResolution {
        panic!("this read must not resolve a workspace model reference");
    }

    #[test]
    fn diagnostic_codes_stay_stable() {
        assert_eq!(
            ControlReadDiagnosticCode::PayloadNotObject.as_str(),
            "payload_not_object"
        );
        assert_eq!(
            ControlReadDiagnosticCode::SchemaVersionMalformed.as_str(),
            "schema_version_malformed"
        );
        assert_eq!(
            ControlReadDiagnosticCode::SchemaVersionUnsupported.as_str(),
            "schema_version_unsupported"
        );
        assert_eq!(
            ControlReadDiagnosticCode::EnabledMalformed.as_str(),
            "enabled_malformed"
        );
        assert_eq!(
            ControlReadDiagnosticCode::ModelRefMalformed.as_str(),
            "model_ref_malformed"
        );
    }

    #[test]
    fn non_object_payloads_fail_closed_and_keep_the_raw_value() {
        for raw in [
            json!(null),
            json!([1, 2]),
            json!(7),
            json!("enabled"),
            json!(true),
        ] {
            let read = read_control_record(&raw, &[]);

            assert_eq!(read.enabled, None);
            assert_eq!(read.model_ref, None);
            assert_eq!(
                codes(&read),
                vec![ControlReadDiagnosticCode::PayloadNotObject]
            );
            assert_eq!(read.preserved, raw);

            let derived = derive_from_read(&read, CapabilityDelivery::Delivered, panic_resolver);
            assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
        }
    }

    #[test]
    fn legacy_payload_without_switch_or_version_is_off_and_preserved() {
        let raw = json!({
            "unknown_key": { "nested": [1, 2, { "deep": null }] },
            "another_unknown_key": "text",
        });

        let read = read_control_record(&raw, &[]);

        assert_eq!(read.enabled, None);
        assert_eq!(read.model_ref, None);
        assert!(read.diagnostics.is_empty());
        assert_eq!(read.preserved, raw);

        let derived = derive_from_read(&read, CapabilityDelivery::Delivered, panic_resolver);
        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
        assert_eq!(derived.model_state, WorkspaceModelState::NotReferenced);
    }

    #[test]
    fn an_accepted_schema_version_projects_the_configured_reference() {
        let raw = json!({
            "schema_version": 1,
            "enabled": true,
            "model_ref": "workspace-model-a",
            "unknown_key": ["kept"],
        });

        let read = read_control_record(&raw, &[1, 2]);

        assert!(read.diagnostics.is_empty());
        assert_eq!(read.enabled, Some(true));
        assert_eq!(projected_ref(&read), Some("workspace-model-a"));
        assert_eq!(read.preserved, raw);
    }

    #[test]
    fn an_unaccepted_schema_version_fails_closed_and_keeps_the_payload() {
        let raw = json!({
            "schema_version": 7,
            "enabled": true,
            "model_ref": "workspace-model-a",
            "unknown_key": ["kept"],
        });

        for accepted in [&[][..], &[1, 2][..]] {
            let read = read_control_record(&raw, accepted);

            assert_eq!(read.enabled, None);
            assert_eq!(read.model_ref, None);
            assert_eq!(
                codes(&read),
                vec![ControlReadDiagnosticCode::SchemaVersionUnsupported]
            );
            assert!(read.diagnostics[0].detail.contains('7'));
            assert_eq!(read.preserved, raw);

            let derived = derive_from_read(&read, CapabilityDelivery::Unavailable, panic_resolver);
            assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
            assert!(!derived.is_degraded());
        }
    }

    #[test]
    fn a_malformed_schema_version_fails_closed_and_keeps_the_payload() {
        for version in [json!("1"), json!(1.5), json!(-1), json!(true), json!(null)] {
            let raw = json!({ "schema_version": version, "enabled": true });

            let read = read_control_record(&raw, &[1]);

            assert_eq!(read.enabled, None);
            assert_eq!(read.model_ref, None);
            assert_eq!(
                codes(&read),
                vec![ControlReadDiagnosticCode::SchemaVersionMalformed]
            );
            assert_eq!(read.preserved, raw);
        }
    }

    #[test]
    fn a_missing_switch_is_a_default_rather_than_a_fault() {
        let raw = json!({ "model_ref": "workspace-model-a", "unknown_key": 1 });

        let read = read_control_record(&raw, &[]);

        assert_eq!(read.enabled, None);
        assert!(read.diagnostics.is_empty());
        assert_eq!(read.model_ref, None);
        assert_eq!(read.preserved, raw);

        let derived = derive_from_read(&read, CapabilityDelivery::Delivered, panic_resolver);
        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
    }

    #[test]
    fn a_malformed_switch_fails_closed_without_reading_the_reference() {
        for enabled in [json!("true"), json!(1), json!(null), json!({})] {
            let raw = json!({ "enabled": enabled, "model_ref": "workspace-model-a" });

            let read = read_control_record(&raw, &[]);

            assert_eq!(read.enabled, None);
            assert_eq!(read.model_ref, None);
            assert_eq!(
                codes(&read),
                vec![ControlReadDiagnosticCode::EnabledMalformed]
            );
            assert_eq!(read.preserved, raw);
        }
    }

    #[test]
    fn a_disabled_switch_projects_no_reference_and_keeps_the_payload() {
        let raw = json!({ "enabled": false, "model_ref": 42, "unknown_key": "kept" });

        let read = read_control_record(&raw, &[]);

        assert_eq!(read.enabled, Some(false));
        assert_eq!(read.model_ref, None);
        assert!(read.diagnostics.is_empty());
        assert_eq!(read.preserved, raw);

        let derived = derive_from_read(&read, CapabilityDelivery::Delivered, panic_resolver);
        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
    }

    #[test]
    fn an_enabled_record_without_a_reference_reads_as_baseline() {
        let raw = json!({ "enabled": true, "unknown_key": "kept" });

        let read = read_control_record(&raw, &[]);

        assert_eq!(read.enabled, Some(true));
        assert_eq!(read.model_ref, None);
        assert!(read.diagnostics.is_empty());
        assert_eq!(read.preserved, raw);

        let derived = derive_from_read(&read, CapabilityDelivery::Delivered, panic_resolver);
        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Baseline);
    }

    #[test]
    fn a_malformed_reference_fails_closed_instead_of_degrading() {
        for model_ref in [
            json!(""),
            json!("   "),
            json!(42),
            json!(null),
            json!(["workspace-model-a"]),
            json!({}),
        ] {
            let raw = json!({
                "enabled": true,
                "model_ref": model_ref,
                "unknown_key": { "kept": true },
            });

            let read = read_control_record(&raw, &[]);

            assert_eq!(read.enabled, None);
            assert_eq!(read.model_ref, None);
            assert_eq!(
                codes(&read),
                vec![ControlReadDiagnosticCode::ModelRefMalformed]
            );
            assert_eq!(read.preserved, raw);

            let derived = derive_from_read(&read, CapabilityDelivery::Delivered, panic_resolver);
            assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
            assert!(!derived.is_degraded());
        }
    }

    #[test]
    fn a_configured_reference_derives_intelligent_or_degraded() {
        let raw = json!({
            "schema_version": 1,
            "enabled": true,
            "model_ref": "workspace-model-a",
            "unknown_key": [1],
        });

        let read = read_control_record(&raw, &[1]);
        assert!(read.diagnostics.is_empty());
        assert_eq!(read.preserved, raw);

        let resolved = derive_from_read(&read, CapabilityDelivery::Delivered, |_| {
            WorkspaceModelResolution::Resolved
        });
        assert_eq!(resolved.tier, WorkspaceIntelligenceTier::Intelligent);
        assert_eq!(resolved.model_state, WorkspaceModelState::Configured);
        assert!(!resolved.is_degraded());
        assert_eq!(
            resolved.model_ref.as_ref().map(WorkspaceModelRef::as_str),
            Some("workspace-model-a")
        );

        let degraded = derive_from_read(&read, CapabilityDelivery::Unavailable, |_| {
            WorkspaceModelResolution::Unresolvable
        });
        assert_eq!(degraded.tier, WorkspaceIntelligenceTier::Intelligent);
        assert_eq!(
            degraded.model_state,
            WorkspaceModelState::ConfiguredUnresolvable
        );
        assert!(degraded.is_degraded());
        assert_eq!(degraded.delivery, CapabilityDelivery::Unavailable);
        assert_eq!(
            degraded.model_ref.as_ref().map(WorkspaceModelRef::as_str),
            Some("workspace-model-a")
        );
    }
}
