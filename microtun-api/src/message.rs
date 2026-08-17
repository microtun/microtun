//! The message envelope.
//!
//! WebSocket already delimits messages, so the envelope carries only what
//! framing cannot: which call a response belongs to, and whether a message
//! expects one at all.
//!
//! ```text
//! request       {"id":1,"method":"peer.by_key","params":{...}}
//! response      {"id":1,"result":{...}}
//! error         {"id":1,"error":{"code":3,"message":"..."}}
//! notification  {"method":"peer.changed","params":{...}}
//! ```
//!
//! A message with an `id` expects exactly one reply naming that `id`. A
//! message without one expects no reply, in either direction.
//!
//! # Deliberately small envelope
//!
//! WebSocket owns framing and the versioned endpoint path owns version
//! negotiation, so this layer carries only call correlation and payload shape.
//! Batches are unsupported, and an absent or explicit-null `id` both mean that
//! no reply is expected.
//!
//! # Two passes
//!
//! Incoming messages are decoded twice, because `serde-json-core` has no
//! `RawValue` to defer a subtree with. The first pass reads only `id` and
//! `method` and lets serde skip everything else; once the message kind and the
//! expected payload type are known, the same bytes are parsed again into a
//! typed shape. The cost is one extra scan of a message that is at most a
//! kilobyte; the benefit is that no allocation and no intermediate value tree
//! is needed anywhere.

use heapless::String;
use serde::{Deserialize, Deserializer, Serialize};

/// Longest remote error message retained by a client. Longer messages are
/// truncated: the code is what a caller acts on, and the text is for a log.
pub const MAX_ERROR_TEXT_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Outgoing
// ---------------------------------------------------------------------------

/// A request (`id` present) or notification (`id` absent).
#[derive(Debug, Serialize)]
pub(crate) struct OutCall<'a, P: Serialize + ?Sized> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    pub method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<&'a P>,
}

/// A successful response.
#[derive(Debug, Serialize)]
pub(crate) struct OutResult<'a, T: Serialize + ?Sized> {
    pub id: u32,
    pub result: &'a T,
}

/// An error response, or — with no `id` — an unattributable error report.
#[derive(Debug, Serialize)]
pub(crate) struct OutError<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    pub error: ErrorObject<'a>,
}

// ---------------------------------------------------------------------------
// Incoming — pass one
// ---------------------------------------------------------------------------

/// Everything the dispatcher needs to know before it knows the payload type.
///
/// `method` borrows from the receive buffer; the caller holds that buffer for
/// as long as it holds this.
#[derive(Debug, Deserialize)]
pub(crate) struct Envelope<'a> {
    #[serde(default)]
    pub id: Option<u32>,
    #[serde(borrow, default)]
    pub method: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Incoming — pass two
// ---------------------------------------------------------------------------

/// `Default` for `Option<T>` without serde-derive inferring a `T: Default`
/// bound on the generic impl.
fn none<T>() -> Option<T> {
    None
}

/// Second-pass extraction of `params`.
#[derive(Debug, Deserialize)]
pub(crate) struct ParamsEnvelope<T> {
    #[serde(default = "none")]
    pub params: Option<T>,
}

/// An `error` member, in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct ErrorObject<'a> {
    /// One of [`crate::codes`].
    pub code: u16,
    /// A short human-readable description. Never machine-parsed.
    #[serde(borrow)]
    pub message: &'a str,
}

/// Decode a *present* `error` member.
///
/// `Option<ErrorObject>` on its own maps both an omitted member and an
/// explicit `"error":null` to `None`. A response contains exactly one of
/// `result` or a real error object, so accepting `"error":null` beside a
/// result would silently promote a malformed response to a successful one —
/// and in this protocol a successful response is the only thing that may
/// delete a held peer record. Missing members are still supplied by `default`;
/// a present one must decode as a real error object.
fn deserialize_present_error<'de, D>(deserializer: D) -> Result<Option<ErrorObject<'de>>, D::Error>
where
    D: Deserializer<'de>,
{
    ErrorObject::deserialize(deserializer).map(Some)
}

/// Second-pass extraction of `result`/`error` from a response.
#[derive(Debug, Deserialize)]
pub(crate) struct ResponseEnvelope<'a, T> {
    #[serde(default = "none")]
    pub result: Option<T>,
    #[serde(
        borrow,
        default = "none",
        deserialize_with = "deserialize_present_error"
    )]
    pub error: Option<ErrorObject<'a>>,
}

/// An `error` object received from the remote endpoint, owned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Peers API error {code}: {message}")]
pub struct RemoteError {
    /// One of [`crate::codes`].
    pub code: u16,
    /// The message, truncated to [`MAX_ERROR_TEXT_LEN`] bytes.
    pub message: String<MAX_ERROR_TEXT_LEN>,
}

impl RemoteError {
    pub(crate) fn new(code: u16, message: &str) -> Self {
        let mut text = String::new();
        for character in message.chars() {
            if text.push(character).is_err() {
                break;
            }
        }
        RemoteError {
            code,
            message: text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(body: &str) -> Envelope<'_> {
        serde_json_core::from_slice::<Envelope<'_>>(body.as_bytes())
            .expect("the envelope parses")
            .0
    }

    #[test]
    fn outgoing_call_uses_only_the_peers_envelope() {
        #[derive(Serialize)]
        struct TestParams {
            value: u8,
        }

        let call = OutCall {
            id: Some(7),
            method: "peer.by_key",
            params: Some(&TestParams { value: 1 }),
        };
        let mut output = [0u8; 128];
        let len = serde_json_core::to_slice(&call, &mut output).expect("call serializes");
        let text = core::str::from_utf8(&output[..len]).expect("JSON is UTF-8");

        assert_eq!(
            text,
            r#"{"id":7,"method":"peer.by_key","params":{"value":1}}"#
        );
    }

    #[test]
    fn requests_and_notifications_are_told_apart_by_id() {
        let request = envelope(r#"{"id":7,"method":"peer.by_key","params":{"public_key":"x"}}"#);
        assert_eq!(request.id, Some(7));
        assert_eq!(request.method, Some("peer.by_key"));

        let notification = envelope(r#"{"method":"peer.changed","params":{"public_key":"x"}}"#);
        assert_eq!(notification.id, None);

        let response = envelope(r#"{"id":7,"result":{"not_found":{}}}"#);
        assert_eq!(response.id, Some(7));
        assert_eq!(response.method, None);
    }

    #[test]
    fn a_null_id_is_simply_absent() {
        assert_eq!(envelope(r#"{"id":null,"method":"peer.unwatch"}"#).id, None);
    }

    #[test]
    fn an_explicit_null_error_is_not_a_success() {
        #[derive(Debug, Deserialize)]
        struct Payload<'a> {
            #[allow(dead_code)]
            #[serde(borrow)]
            status: &'a str,
        }

        let valid = br#"{"result":{"status":"ok"}}"#;
        assert!(
            serde_json_core::from_slice::<ResponseEnvelope<'_, Payload<'_>>>(valid).is_ok(),
            "the control response parses"
        );

        let with_null = br#"{"result":{"status":"ok"},"error":null}"#;
        assert!(
            serde_json_core::from_slice::<ResponseEnvelope<'_, Payload<'_>>>(with_null).is_err(),
            "an explicit null error must make the response malformed"
        );
    }

    #[test]
    fn remote_error_text_is_truncated_rather_than_refused() {
        let long = "e".repeat(MAX_ERROR_TEXT_LEN * 2);
        let error = RemoteError::new(crate::codes::INTERNAL, &long);
        assert_eq!(error.code, crate::codes::INTERNAL);
        assert_eq!(error.message.len(), MAX_ERROR_TEXT_LEN);
    }
}
