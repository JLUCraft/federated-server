use axum::http::{HeaderMap, StatusCode};
use subtle::ConstantTimeEq;

/// Constant-time check of an `Authorization: Bearer <token>` header against the expected secret.
pub(crate) fn require_bearer(headers: &HeaderMap, expected: &[u8]) -> Result<(), StatusCode> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if bool::from(token.as_bytes().ct_eq(expected)) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
