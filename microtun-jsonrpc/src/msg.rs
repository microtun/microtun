//! Wire-level message shapes.
//!
//! Incoming messages are handled in **two passes** so we never need
//! `RawValue` (which `serde-json-core` does not have):
//!
//! 1. Parse an [`Envelope`] that only looks at `jsonrpc`, `method` and `id`;
//!    all other fields (`params`, `result`, `error`) are skipped by serde.
//! 2. Once the message kind and the expected concrete type are known, parse
//!    the *same* bytes again into a typed structure ([`ParamsEnvelope`] or
//!    [`ResponseEnvelope`]).

use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const VERSION: &str = "2.0";

// ---------------------------------------------------------------------------
// Outgoing
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct OutRequest<'a, P: Serialize + ?Sized> {
    pub jsonrpc: &'static str,
    pub method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<&'a P>,
    /// `None` for notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<&'a i64>,
}

#[derive(Serialize)]
pub(crate) struct OutResponse<'a, T: Serialize + ?Sized> {
    pub jsonrpc: &'static str,
    pub id: &'a i64,
    pub result: &'a T,
}

#[derive(Serialize)]
pub(crate) struct OutErrorObj<'a> {
    pub code: i32,
    pub message: &'a str,
}

#[derive(Serialize)]
pub(crate) struct OutErrorResponse<'a> {
    pub jsonrpc: &'static str,
    /// `None` serializes as `"id": null` (per spec when the id is unknown).
    pub id: Option<&'a i64>,
    pub error: OutErrorObj<'a>,
}

// ---------------------------------------------------------------------------
// Incoming — pass 1
// ---------------------------------------------------------------------------

/// First-pass view of any incoming message.
///
/// JSON-RPC message ids are signed 64-bit JSON integers. An omitted id is a
/// notification; any present value that cannot deserialize as `i64` is an
/// invalid JSON-RPC envelope.
pub(crate) struct Envelope<'a> {
    pub method: Option<&'a str>,
    pub id: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct EnvelopeNumId<'a> {
    #[serde(borrow, default)]
    pub jsonrpc: Option<&'a str>,
    #[serde(borrow, default)]
    pub method: Option<&'a str>,
    #[serde(default)]
    pub id: Option<i64>,
}

/// Detects an *explicit* `"id": null`.
///
/// `Option<i64>` cannot tell an absent member from a null one — both
/// deserialize to `None` — yet the two mean different things: a notification
/// must omit `id`, so a message that spells it out as null is a malformed
/// envelope rather than a notification.
///
/// The field type is `()` rather than `Option<()>`, and the difference is
/// load-bearing. Serde resolves a missing field through `missing_field`,
/// which special-cases exactly one method — `deserialize_option`, answered
/// with `visit_none`. Anything built on `Option` therefore *succeeds* on an
/// absent member, which would make this match every notification. `()` routes
/// through `deserialize_unit` instead: that accepts JSON null and nothing
/// else, and a missing field falls through to `deserialize_any`, which is an
/// error. Success here means precisely "`id` is present and null".
#[derive(Deserialize)]
pub(crate) struct EnvelopeNullId {
    #[allow(dead_code)]
    pub id: (),
}

/// A frame that is a syntactically valid JSON *object*, whatever it contains.
///
/// Used only to separate "this is not JSON" from "this is JSON that is not a
/// JSON-RPC envelope", which are `-32700` and `-32600` respectively. Unknown
/// members are skipped, so any object parses.
#[derive(Deserialize)]
pub(crate) struct AnyObject {}

// ---------------------------------------------------------------------------
// Incoming — pass 2
// ---------------------------------------------------------------------------

/// `Default` for `Option<T>` without serde-derive inferring a `T: Default`
/// bound on the generic impl.
fn none<T>() -> Option<T> {
    None
}

/// Second-pass extraction of `params` from a request/notification frame.
#[derive(Deserialize)]
pub(crate) struct ParamsEnvelope<T> {
    #[serde(default = "none")]
    pub params: Option<T>,
}

#[derive(Deserialize)]
pub(crate) struct InErrorObj<'a> {
    pub code: i32,
    #[serde(borrow, default)]
    pub message: Option<&'a str>,
}

/// Decode a present JSON-RPC `error` member.
///
/// `Option<InErrorObj>` by itself maps both an omitted member and an explicit
/// `"error": null` to `None`. JSON-RPC requires a response to contain exactly
/// one of `result` or a non-null error object, so accepting `error: null`
/// alongside a result would incorrectly turn an invalid response into a
/// successful one. Missing members are still supplied by `default`; a present
/// member must deserialize as a real error object.
fn deserialize_present_error<'de, D>(deserializer: D) -> Result<Option<InErrorObj<'de>>, D::Error>
where
    D: Deserializer<'de>,
{
    InErrorObj::deserialize(deserializer).map(Some)
}

/// Second-pass extraction of `result`/`error` from a response frame.
#[derive(Deserialize)]
pub(crate) struct ResponseEnvelope<'a, T> {
    #[serde(default = "none")]
    pub result: Option<T>,
    #[serde(
        borrow,
        default = "none",
        deserialize_with = "deserialize_present_error"
    )]
    pub error: Option<InErrorObj<'a>>,
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::ResponseEnvelope;

    #[derive(Deserialize)]
    struct ResultValue<'a> {
        #[allow(dead_code)]
        #[serde(borrow)]
        status: &'a str,
    }

    #[test]
    fn explicit_null_error_is_not_a_success_response() {
        let valid = br#"{"result":{"status":"not_found"}}"#;
        assert!(
            serde_json_core::from_slice::<ResponseEnvelope<'_, ResultValue<'_>>>(valid).is_ok(),
            "the control response should parse"
        );

        let frame = br#"{"result":{"status":"not_found"},"error":null}"#;
        assert!(
            serde_json_core::from_slice::<ResponseEnvelope<'_, ResultValue<'_>>>(frame).is_err(),
            "an explicit null error member must make the response malformed"
        );
    }
}
