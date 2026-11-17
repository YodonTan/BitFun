use openbitfun_core_types::{
    SessionUsageReport, UsageContextCategory, UsageCoverageLevel, UsageRequestInputSource,
    UsageRequestRef, UsageRequestSnapshot, UsageRequestSnapshotPreview,
    UsageRequestSnapshotReadRequest, UsageRequestSnapshotView, UsageRequestUsageState,
    UsageSummaryState, UsageToolCategory, REQUEST_CONTEXT_ESTIMATION_VERSION,
    REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION, SESSION_USAGE_REPORT_SCHEMA_VERSION,
};

#[test]
fn session_usage_report_is_a_shared_stable_contract() {
    let mut report = SessionUsageReport::partial_unavailable("session-1", 1_778_347_200_000);
    report.report_id = "usage-session-1-1778347200000".to_string();

    let json = serde_json::to_value(&report).expect("serialize usage report");
    let restored: SessionUsageReport =
        serde_json::from_value(json.clone()).expect("deserialize usage report");

    assert_eq!(restored, report);
    assert_eq!(
        json["schemaVersion"],
        serde_json::json!(SESSION_USAGE_REPORT_SCHEMA_VERSION)
    );
    assert_eq!(json["sessionId"], "session-1");
    assert_eq!(report.coverage.level, UsageCoverageLevel::Partial);
}

#[test]
fn usage_tool_category_keeps_the_persisted_wire_values() {
    assert_eq!(
        serde_json::to_value(UsageToolCategory::Git).expect("serialize category"),
        "git"
    );
}

#[test]
fn context_composition_keeps_legacy_reports_readable() {
    let report = SessionUsageReport::partial_unavailable("legacy", 42);
    let legacy = serde_json::to_value(&report).unwrap();
    assert!(legacy.get("context").is_none());
    assert!(legacy.get("systemPromptPreview").is_none());
    assert!(legacy.get("contextPreview").is_none());
    let mut restored: SessionUsageReport = serde_json::from_value(legacy.clone()).unwrap();
    assert!(restored.context.is_none());
    assert!(restored.context_estimate.is_none());
    assert!(restored.system_prompt_preview.is_none());
    assert!(restored.context_preview.is_none());
    assert_eq!(serde_json::to_value(&restored).unwrap(), legacy);
    restored.context = Some(openbitfun_core_types::UsageContextBreakdown {
        system_prompt: 100,
        conversation: 900,
        context_window: Some(128_000),
        ..Default::default()
    });
    let encoded = serde_json::to_value(&restored).unwrap();
    assert_eq!(encoded["context"]["systemPrompt"], 100);
    assert_eq!(
        serde_json::from_value::<SessionUsageReport>(encoded).unwrap(),
        restored
    );
}

#[test]
fn system_prompt_preview_round_trips_without_changing_default_report_privacy() {
    let mut report = SessionUsageReport::partial_unavailable("session-1", 42);
    assert!(!report.privacy.prompt_content_included);
    report.system_prompt_preview = Some(openbitfun_core_types::UsageSystemPromptPreview {
        content: "# System\nExact cached instructions\n".into(),
        cached_at: 123,
    });
    report.privacy.prompt_content_included = true;
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["systemPromptPreview"]["cachedAt"], 123);
    assert_eq!(
        serde_json::from_value::<SessionUsageReport>(json).unwrap(),
        report
    );
}

#[test]
fn context_preview_round_trips_with_explicit_category_and_capture_time() {
    let mut report = SessionUsageReport::partial_unavailable("session-1", 42);
    report.context_preview = Some(openbitfun_core_types::UsageContextPreview {
        category: openbitfun_core_types::UsageContextCategory::ToolDefinitions,
        content: "```json\n[]\n```".into(),
        captured_at: 123,
    });
    let encoded = serde_json::to_value(&report).unwrap();
    assert_eq!(encoded["contextPreview"]["category"], "toolDefinitions");
    assert_eq!(encoded["contextPreview"]["capturedAt"], 123);
    assert_eq!(
        serde_json::from_value::<SessionUsageReport>(encoded).unwrap(),
        report
    );
}

#[test]
fn current_context_estimate_is_additive_and_preview_is_optional() {
    let mut report = SessionUsageReport::partial_unavailable("session-1", 42);
    assert!(serde_json::to_value(&report)
        .unwrap()
        .get("contextEstimate")
        .is_none());
    report.context_estimate = Some(openbitfun_core_types::UsageContextEstimate {
        captured_at: 42,
        composition: Some(openbitfun_core_types::UsageContextBreakdown {
            conversation: 900,
            ..Default::default()
        }),
        contents: Default::default(),
        unavailable_reason: None,
    });
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["contextEstimate"]["composition"]["conversation"], 900);
    assert!(value["contextEstimate"].get("contents").is_none());
    assert_eq!(
        serde_json::from_value::<SessionUsageReport>(value).unwrap(),
        report
    );
}

fn request_ref() -> UsageRequestRef {
    UsageRequestRef {
        execution_host_id: "local".to_string(),
        workspace_id: Some("workspace-1".to_string()),
        session_id: "session-1".to_string(),
        turn_id: "turn-1".to_string(),
        round_id: "round-1".to_string(),
        attempt_id: "round-1:attempt:2".to_string(),
        attempt_index: 2,
        started_at: 1_778_347_200_000,
    }
}

fn snapshot() -> UsageRequestSnapshot {
    UsageRequestSnapshot {
        schema_version: REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
        request: request_ref(),
        captured_at: 1_778_347_200_500,
        input_source: UsageRequestInputSource::ModelRequest,
        input_total: Some(120_000),
        context_window: Some(200_000),
        cached_input_tokens: Some(4_000),
        usage_state: UsageRequestUsageState::ProviderReported,
        estimated_total: Some(118_000),
        estimation_version: Some(REQUEST_CONTEXT_ESTIMATION_VERSION),
        summary_state: UsageSummaryState::Ready,
        categories: Some(openbitfun_core_types::UsageContextBreakdown {
            system_prompt: 10_000,
            conversation: 108_000,
            ..Default::default()
        }),
        unavailable_reason: None,
    }
}

#[test]
fn recorded_request_snapshot_is_additive_for_legacy_reports() {
    let report = SessionUsageReport::partial_unavailable("legacy", 42);
    let legacy = serde_json::to_value(&report).unwrap();
    assert!(legacy.get("requestSnapshot").is_none());
    let restored: SessionUsageReport = serde_json::from_value(legacy.clone()).unwrap();
    assert!(restored.request_snapshot.is_none());
    assert_eq!(serde_json::to_value(&restored).unwrap(), legacy);
}

#[test]
fn recorded_request_snapshot_view_round_trips_with_camel_case_identity() {
    let mut report = SessionUsageReport::partial_unavailable("session-1", 42);
    report.request_snapshot = Some(UsageRequestSnapshotView {
        snapshot: snapshot(),
        preview: None,
    });

    let value = serde_json::to_value(&report).unwrap();
    let encoded = &value["requestSnapshot"]["snapshot"];
    assert_eq!(
        encoded["schemaVersion"],
        serde_json::json!(REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION)
    );
    assert_eq!(encoded["request"]["executionHostId"], "local");
    assert_eq!(encoded["request"]["workspaceId"], "workspace-1");
    assert_eq!(encoded["request"]["attemptId"], "round-1:attempt:2");
    assert_eq!(encoded["request"]["attemptIndex"], 2);
    assert_eq!(encoded["request"]["startedAt"], 1_778_347_200_000_i64);
    assert_eq!(encoded["inputSource"], "model_request");
    assert_eq!(encoded["inputTotal"], 120_000);
    assert_eq!(encoded["contextWindow"], 200_000);
    assert_eq!(encoded["cachedInputTokens"], 4_000);
    assert_eq!(encoded["usageState"], "provider_reported");
    assert_eq!(encoded["estimatedTotal"], 118_000);
    assert_eq!(encoded["summaryState"], "ready");
    assert_eq!(encoded["categories"]["systemPrompt"], 10_000);
    assert!(value["requestSnapshot"].get("preview").is_none());
    assert_eq!(
        serde_json::from_value::<SessionUsageReport>(value).unwrap(),
        report
    );
}

#[test]
fn request_snapshot_preview_echoes_the_actual_request_identity() {
    let mut requested = request_ref();
    requested.attempt_id = "round-1:attempt:1".to_string();
    requested.attempt_index = 1;
    let read = UsageRequestSnapshotReadRequest {
        request: Some(requested),
        category: Some(UsageContextCategory::ToolDefinitions),
    };
    let encoded = serde_json::to_value(&read).unwrap();
    assert_eq!(encoded["request"]["attemptId"], "round-1:attempt:1");
    assert_eq!(encoded["category"], "toolDefinitions");
    assert_eq!(
        serde_json::from_value::<UsageRequestSnapshotReadRequest>(encoded).unwrap(),
        read
    );
    assert_eq!(
        serde_json::to_value(UsageRequestSnapshotReadRequest::default()).unwrap(),
        serde_json::json!({})
    );

    let view = UsageRequestSnapshotView {
        snapshot: snapshot(),
        preview: Some(UsageRequestSnapshotPreview {
            category: UsageContextCategory::ToolDefinitions,
            content: "```json\n[]\n```".to_string(),
            captured_at: 1_778_347_200_600,
            request: request_ref(),
            unavailable_reason: None,
        }),
    };
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(value["preview"]["category"], "toolDefinitions");
    assert_eq!(value["preview"]["capturedAt"], 1_778_347_200_600_u64);
    assert_eq!(
        value["preview"]["request"]["attemptId"],
        "round-1:attempt:2"
    );
    assert_eq!(
        value["preview"]["request"]["attemptIndex"],
        serde_json::json!(2)
    );
    assert_eq!(
        serde_json::from_value::<UsageRequestSnapshotView>(value).unwrap(),
        view
    );
}

#[test]
fn unknown_usage_state_serializes_as_unknown_and_never_fabricates_a_zero() {
    assert_eq!(
        serde_json::to_value(UsageRequestUsageState::Unknown).unwrap(),
        serde_json::json!("unknown")
    );

    let unknown = UsageRequestSnapshot {
        schema_version: REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
        request: request_ref(),
        captured_at: 7,
        input_source: UsageRequestInputSource::Unknown,
        input_total: None,
        context_window: Some(200_000),
        cached_input_tokens: None,
        usage_state: UsageRequestUsageState::Unknown,
        estimated_total: None,
        estimation_version: None,
        summary_state: UsageSummaryState::Unavailable,
        categories: None,
        unavailable_reason: Some("usage_unavailable".to_string()),
    };
    let value = serde_json::to_value(&unknown).unwrap();
    assert_eq!(value["usageState"], "unknown");
    assert_eq!(value["inputSource"], "unknown");
    assert_eq!(value["summaryState"], "unavailable");
    assert!(value.get("inputTotal").is_none());
    assert!(value.get("estimatedTotal").is_none());
    assert!(value.get("categories").is_none());
    assert_eq!(
        value["contextWindow"],
        serde_json::json!(200_000),
        "a pending or unknown snapshot may still carry the attempt's context capacity"
    );
    assert_eq!(
        serde_json::from_value::<UsageRequestSnapshot>(value).unwrap(),
        unknown
    );

    // A newer host may name a state this build does not know; it degrades to
    // unknown instead of failing or becoming a reported zero.
    let future: UsageRequestUsageState =
        serde_json::from_value(serde_json::json!("future_state")).unwrap();
    assert_eq!(future, UsageRequestUsageState::Unknown);
    let future_source: UsageRequestInputSource =
        serde_json::from_value(serde_json::json!("future_source")).unwrap();
    assert_eq!(future_source, UsageRequestInputSource::Unknown);
}

#[test]
fn request_identity_ignores_started_at_only() {
    let base = request_ref();
    let mut later_start = base.clone();
    later_start.started_at += 5_000;
    assert!(base.same_identity(&later_start));

    let mutations: [fn(&mut UsageRequestRef); 5] = [
        |value: &mut UsageRequestRef| value.execution_host_id = "peer-host".to_string(),
        |value: &mut UsageRequestRef| value.workspace_id = None,
        |value: &mut UsageRequestRef| value.session_id = "session-2".to_string(),
        |value: &mut UsageRequestRef| value.turn_id = "turn-2".to_string(),
        |value: &mut UsageRequestRef| value.round_id = "round-2".to_string(),
    ];
    for mutate in mutations {
        let mut other = base.clone();
        mutate(&mut other);
        assert!(!base.same_identity(&other));
    }

    // A later attempt index alone is not identity either: the attempt id decides.
    let mut next_attempt = base.clone();
    next_attempt.attempt_id = "round-1:attempt:3".to_string();
    next_attempt.attempt_index = 3;
    assert!(!base.same_identity(&next_attempt));
    assert!(!next_attempt.same_identity(&base));
}

#[test]
fn recorded_request_snapshot_ignores_unknown_and_extra_fields() {
    let future = serde_json::json!({
        "schemaVersion": 1,
        "request": {
            "executionHostId": "local",
            "sessionId": "session-1",
            "turnId": "turn-1",
            "roundId": "round-1",
            "attemptId": "round-1:attempt:2",
            "attemptIndex": 2,
            "startedAt": 5,
            "futureRefField": true
        },
        "capturedAt": 9,
        "inputSource": "model_request",
        "usageState": "provider_reported",
        "inputTotal": 42,
        "summaryState": "ready",
        "futureSnapshotField": { "nested": 1 }
    });
    let snapshot: UsageRequestSnapshot = serde_json::from_value(future).unwrap();
    assert_eq!(snapshot.input_total, Some(42));
    assert_eq!(snapshot.request.workspace_id, None);
    assert_eq!(snapshot.request.attempt_index, 2);
    assert_eq!(
        snapshot.context_window, None,
        "a snapshot recorded before the attempt context window was captured stays readable"
    );
}
