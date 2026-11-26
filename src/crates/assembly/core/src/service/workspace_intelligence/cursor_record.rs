//! Recorded cursor envelope for workspace intelligence (WP1.5-b, second slice).
//!
//! This module is the pure, IO-free half of a persisted cursor: it turns one source
//! and one marker into the text the cognition partition stores, and turns stored text
//! back into the pair it names. It writes nothing, reads nothing, takes no lock, has
//! no clock and has no consumer in this tree yet.
//!
//! # Shape
//!
//! ```text
//! {"v":1,"source":"session_snapshot","marker":"s1-usable-2-0-<64 hex>"}
//! ```
//!
//! The envelope is a plain JSON subset with a fixed key order, no whitespace and no
//! escape sequences. The cursor contract's own value rules do allow `"` and `\`, so
//! this is a restriction of the envelope rather than of the marker: a value that would
//! need escaping is refused by [`encode`] (`invalid_envelope`) instead of being
//! escaped. That keeps decoding total and allocation-free — a stored value either
//! parses into borrowed slices of itself or is [`RecordedCursor::Foreign`] — at the
//! cost of refusing a marker this module cannot represent. Anything this module did
//! not write is [`RecordedCursor::Foreign`]: it is preserved verbatim and may only be
//! replaced as a whole.
//!
//! # What this slice deliberately does not deliver
//!
//! - no write and no persistence: the store's own compare-and-swap primitive is the
//!   only writer, and recording is the caller's act;
//! - no decision: `cursor::decide_step` decides, and this module only names what that
//!   decision produced;
//! - no runtime wrapper over the claim-gated cursor advance. The acceptance logic
//!   lives in the services layer, and a wrapper here would be an async function with
//!   no caller and an `OriginTicket` lifetime to carry. The intended future consumer
//!   is `session_source::offered_step` -> `cursor::decide_step` -> this module's
//!   affinity check -> encode -> the governed cursor advance;
//! - no gap record and no dedup window: a `Foreign` value is never interpreted, only
//!   replaced.
//!
//! # Same-transaction obligation, transferred
//!
//! This slice makes one cursor advance atomic, fenced and compare-and-swapped. The
//! cursor contract also requires that an applied cognition update and the cursor it
//! covers commit in one partition transaction. There is nothing to bind that to yet:
//! the cognition partition holds only `cursor` and `incarnation_token`, with no
//! cognition content store. That obligation therefore belongs to the later content
//! store: its write path must commit content and cursor inside the same
//! `BEGIN IMMEDIATE` and use the cursor advance's compare-and-swap as that
//! transaction's optimistic concurrency check. Today `advance_cursor` opens and commits
//! its own `IMMEDIATE` transaction, so a merged write must be a NEW primitive that
//! writes content and then the cursor inside one transaction and reuses the same
//! compare-and-swap semantics; wrapping or nesting `advance_cursor` inside an outer
//! transaction is not an option, because SQLite has no nested write transaction here and
//! the inner commit would end the outer unit of work.

use super::cursor::{SourceId, SourceMarker};

/// Version of the recorded cursor envelope this module writes.
pub(crate) const CURSOR_ENVELOPE_VERSION: u32 = 1;

/// Largest stored envelope this module accepts, in bytes.
///
/// The bound is small on purpose: an envelope names a source and one diagnostic
/// marker, not a payload.
const MAX_ENVELOPE_BYTES: usize = 1024;

/// The recorded cursor of one source, as far as this module can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordedCursor<'a> {
    /// The column held SQL NULL: nothing was ever recorded.
    None,
    /// Stored text this module wrote: one source and one marker, both borrowed from it.
    Parsed { source: &'a str, marker: &'a str },
    /// Stored text this module did not write. It is preserved verbatim and is never
    /// read as a partial or best-effort value.
    Foreign(&'a str),
}

/// Why this module refused to encode or accept a cursor record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorRecordRefusal {
    /// The encoded envelope would exceed [`MAX_ENVELOPE_BYTES`].
    EnvelopeTooLong,
    /// The stored envelope names a source other than the one this record is for.
    SourceMismatch,
    /// A value cannot be represented in the envelope subset, or the bytes this module
    /// just produced did not decode back to what it encoded.
    InvalidEnvelope,
}

impl CursorRecordRefusal {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::EnvelopeTooLong => "envelope_too_long",
            Self::SourceMismatch => "cursor_source_mismatch",
            Self::InvalidEnvelope => "invalid_envelope",
        }
    }
}

/// Decodes one stored cursor value with no affinity check.
///
/// Deliberately private: [`CursorRecord::decode`] is the only decode entry point of this
/// module, so a caller cannot obtain a `Parsed` value without the source affinity check
/// that makes it this source's progress.
fn decode_raw(raw: Option<&str>) -> RecordedCursor<'_> {
    let Some(raw) = raw else {
        return RecordedCursor::None;
    };
    if raw.len() > MAX_ENVELOPE_BYTES {
        return RecordedCursor::Foreign(raw);
    }
    match parse_envelope(raw) {
        Some((source, marker)) => RecordedCursor::Parsed { source, marker },
        None => RecordedCursor::Foreign(raw),
    }
}

/// Encodes one source and one marker into the stored text.
pub(crate) fn encode(
    source: &SourceId,
    marker: &SourceMarker,
) -> Result<String, CursorRecordRefusal> {
    let source = source.as_str();
    let marker = marker.as_str();
    // The envelope is a JSON subset: a value that would need an escape is refused
    // rather than escaped, so decoding never has to unescape and can borrow.
    if contains_escape_byte(source) || contains_escape_byte(marker) {
        return Err(CursorRecordRefusal::InvalidEnvelope);
    }
    let encoded = format!(
        "{{\"v\":{CURSOR_ENVELOPE_VERSION},\"source\":\"{source}\",\"marker\":\"{marker}\"}}"
    );
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(CursorRecordRefusal::EnvelopeTooLong);
    }
    // Self-check: the bytes this module writes must decode to the same two values.
    match parse_envelope(&encoded) {
        Some((decoded_source, decoded_marker))
            if decoded_source == source && decoded_marker == marker =>
        {
            Ok(encoded)
        }
        _ => Err(CursorRecordRefusal::InvalidEnvelope),
    }
}

/// True when a value carries a byte the envelope subset cannot represent.
fn contains_escape_byte(value: &str) -> bool {
    value.contains('"') || value.contains('\\')
}

/// Parses exactly one envelope: fixed key order, no whitespace, no escapes, no extras.
///
/// Every stored value that this module did not write fails here and becomes
/// [`RecordedCursor::Foreign`]; nothing is normalized or repaired.
fn parse_envelope(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.strip_prefix("{\"v\":1,\"source\":\"")?;
    let (source, rest) = split_plain(rest)?;
    let rest = rest.strip_prefix(",\"marker\":\"")?;
    let (marker, rest) = split_plain(rest)?;
    if rest != "}" {
        return None;
    }
    // The stored values must satisfy the cursor contract's own value rules, so a record
    // can never hand a caller a source or marker the contract would have refused.
    SourceId::parse(source).ok()?;
    SourceMarker::parse(marker).ok()?;
    Some((source, marker))
}

/// Splits at the next quote and refuses an escape sequence, keeping bytes verbatim.
fn split_plain(text: &str) -> Option<(&str, &str)> {
    let end = text.find('"')?;
    let value = &text[..end];
    if contains_escape_byte(value) {
        return None;
    }
    Some((value, &text[end + 1..]))
}

/// One source's view of a stored cursor record.
///
/// The record carries the source the caller is deciding for, so a stored envelope that
/// names another source is refused instead of being read as this source's progress.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CursorRecord<'a> {
    source: &'a SourceId,
}

impl<'a> CursorRecord<'a> {
    /// Binds the record to the source this caller is deciding for.
    pub(crate) fn new(source: &'a SourceId) -> Self {
        Self { source }
    }

    /// Decodes one stored value with this record's affinity check.
    ///
    /// `None` stays [`RecordedCursor::None`] and a [`RecordedCursor::Foreign`] value is
    /// returned unchanged: neither can be attributed to this source, and neither is
    /// silently treated as "no cursor" or as this source's marker.
    pub(crate) fn decode<'b>(
        &self,
        raw: Option<&'b str>,
    ) -> Result<RecordedCursor<'b>, CursorRecordRefusal> {
        match decode_raw(raw) {
            RecordedCursor::Parsed { source, .. } if source != self.source.as_str() => {
                Err(CursorRecordRefusal::SourceMismatch)
            }
            other => Ok(other),
        }
    }

    /// Encodes a marker for this record's source.
    pub(crate) fn encode(
        &self,
        marker: &SourceMarker,
    ) -> Result<String, CursorRecordRefusal> {
        encode(self.source, marker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::service::workspace_intelligence::cursor::{
        decide_step, OfferedStep, ReplayCapability, ResumeEvidence, StepDecision,
    };

    const SOURCE: &str = "session_snapshot";
    const MARKER: &str =
        "s1-usable-2-0-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn source(raw: &str) -> SourceId {
        SourceId::parse(raw).expect("the fixture source is valid")
    }

    fn marker(raw: &str) -> SourceMarker {
        SourceMarker::parse(raw).expect("the fixture marker is valid")
    }

    /// Decodes through the module's single affinity-checked entry point.
    fn decode(raw: Option<&str>) -> Result<RecordedCursor<'_>, CursorRecordRefusal> {
        CursorRecord::new(&source(SOURCE)).decode(raw)
    }

    #[test]
    fn an_encoded_envelope_decodes_back_to_the_same_pair() {
        let owner = source(SOURCE);
        let value = marker(MARKER);

        let encoded = encode(&owner, &value).expect("the fixture encodes");

        assert_eq!(
            encoded,
            format!("{{\"v\":1,\"source\":\"{SOURCE}\",\"marker\":\"{MARKER}\"}}")
        );
        assert_eq!(
            decode(Some(encoded.as_str())),
            Ok(RecordedCursor::Parsed {
                source: SOURCE,
                marker: MARKER
            })
        );
        assert_eq!(
            encode(&owner, &value).expect("encoding is deterministic"),
            encoded,
            "two encodings of one pair are byte identical"
        );
        assert_eq!(
            CursorRecord::new(&owner).encode(&value).expect("the record encodes"),
            encoded
        );
        assert_eq!(CURSOR_ENVELOPE_VERSION, 1);
    }

    #[test]
    fn a_null_cursor_decodes_to_none() {
        assert_eq!(decode(None), Ok(RecordedCursor::None));
    }

    #[test]
    fn every_foreign_value_is_preserved_verbatim() {
        let at_bound = format!(
            "{{\"v\":1,\"source\":\"{SOURCE}\",\"marker\":\"{}\"}}",
            "m".repeat(300)
        );
        let too_long = format!(
            "{{\"v\":1,\"source\":\"{SOURCE}\",\"marker\":\"{}\"}}",
            "m".repeat(MAX_ENVELOPE_BYTES)
        );
        let long_source = "s".repeat(65);
        for raw in [
            "",
            "not json",
            "[1,2]",
            "{}",
            "{\"v\":1,\"source\":\"session_snapshot\"}",
            "{\"v\":1,\"source\":\"session_snapshot\",\"marker\":\"m\",\"extra\":1}",
            "{\"v\":2,\"source\":\"session_snapshot\",\"marker\":\"m\"}",
            "{\"v\":\"1\",\"source\":\"session_snapshot\",\"marker\":\"m\"}",
            "{\"v\":1,\"source\":\"\",\"marker\":\"m\"}",
            "{\"v\":1,\"source\":\"session_snapshot\",\"marker\":\"\"}",
            "{\"v\":1,\"source\":\"session_snapshot\",\"marker\":\"a\u{1}b\"}",
            "{\"v\":1,\"source\":\"session_snapshot\",\"marker\":\"a\\b\"}",
            "{\"v\": 1, \"source\": \"session_snapshot\", \"marker\": \"m\"}",
        ] {
            assert_eq!(decode(Some(raw)), Ok(RecordedCursor::Foreign(raw)), "{raw}");
        }
        assert_eq!(
            decode(Some(at_bound.as_str())),
            Ok(RecordedCursor::Foreign(at_bound.as_str()))
        );
        assert_eq!(
            decode(Some(too_long.as_str())),
            Ok(RecordedCursor::Foreign(too_long.as_str()))
        );
        let foreign_source = format!("{{\"v\":1,\"source\":\"{long_source}\",\"marker\":\"m\"}}");
        assert_eq!(
            decode(Some(foreign_source.as_str())),
            Ok(RecordedCursor::Foreign(foreign_source.as_str()))
        );
    }

    #[test]
    fn a_value_the_envelope_cannot_represent_is_refused() {
        let owner = source(SOURCE);
        assert_eq!(
            encode(&owner, &marker("a\"b")),
            Err(CursorRecordRefusal::InvalidEnvelope)
        );
        assert_eq!(
            encode(&owner, &marker("a\\b")),
            Err(CursorRecordRefusal::InvalidEnvelope)
        );
        assert_eq!(
            CursorRecordRefusal::InvalidEnvelope.code(),
            "invalid_envelope"
        );
        assert_eq!(
            CursorRecordRefusal::SourceMismatch.code(),
            "cursor_source_mismatch"
        );
        assert_eq!(
            CursorRecordRefusal::EnvelopeTooLong.code(),
            "envelope_too_long"
        );
    }

    #[test]
    fn a_record_refuses_an_envelope_of_another_source() {
        let other = format!("{{\"v\":1,\"source\":\"workspace_catalog\",\"marker\":\"{MARKER}\"}}");
        assert_eq!(
            CursorRecord::new(&source(SOURCE)).decode(Some(other.as_str())),
            Err(CursorRecordRefusal::SourceMismatch)
        );
        let own = format!("{{\"v\":1,\"source\":\"{SOURCE}\",\"marker\":\"{MARKER}\"}}");
        assert_eq!(
            CursorRecord::new(&source(SOURCE)).decode(Some(own.as_str())),
            Ok(RecordedCursor::Parsed {
                source: SOURCE,
                marker: MARKER
            })
        );
    }

    #[test]
    fn the_marker_a_decision_produces_survives_the_envelope() {
        let owner = source(SOURCE);
        let recorded = marker("m-1");
        let next = marker("m-2");
        let record = CursorRecord::new(&owner);

        // A resumable source that still holds the recorded marker yields a new marker.
        let incremental = decide_step(&owner, Some(&recorded), OfferedStep {
            capability: ReplayCapability::Resumable,
            marker: Some(&next),
            evidence: ResumeEvidence::RecordedMarkerServed,
        })
        .expect("a served marker resumes");
        let StepDecision::Incremental { marker: advanced, .. } = incremental else {
            panic!("a served marker must resume, got {incremental:?}");
        };
        let encoded = record.encode(advanced).expect("the decision marker encodes");
        assert_eq!(
            record.decode(Some(encoded.as_str())),
            Ok(RecordedCursor::Parsed { source: SOURCE, marker: "m-2" })
        );

        // A snapshot-only source reconciles instead, and its offered marker encodes too.
        let reconcile = decide_step(&owner, None, OfferedStep {
            capability: ReplayCapability::SnapshotOnly,
            marker: Some(&next),
            evidence: ResumeEvidence::NotProvided,
        })
        .expect("a snapshot-only step reconciles");
        assert_eq!(reconcile.code(), "snapshot_reconcile");
        let encoded = record.encode(&next).expect("the offered marker encodes");
        assert_eq!(
            record.decode(Some(encoded.as_str())),
            Ok(RecordedCursor::Parsed { source: SOURCE, marker: "m-2" })
        );
    }

    #[test]
    fn the_module_names_no_io_lock_clock_or_public_api() {
        let source_text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/service/workspace_intelligence/cursor_record.rs"
        ))
        .expect("the module source is readable");
        let production = source_text
            .split("#[cfg(test)]")
            .next()
            .expect("the production part precedes the test module");
        let code: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for token in [
            "std::fs",
            "OpenOptions",
            "FileLock",
            "tokio",
            "SystemTime::now",
            "Instant::now",
            "tracing",
            "Serialize",
            "Deserialize",
        ] {
            assert!(!code.contains(token), "the pure module must not name `{token}`");
        }
        // No public item: every declaration is crate-internal.
        assert!(!code.contains("pub fn"), "no public function");
        assert!(!code.contains("pub struct"), "no public struct");
        assert!(!code.contains("pub enum"), "no public enum");
        assert!(!code.contains("pub const"), "no public constant");
    }
}
