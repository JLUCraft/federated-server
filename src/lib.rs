#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Shared embedded and standalone Minecraft room runtime.
mod bearer;
pub mod forwarding;
pub mod native;
pub mod ops;
pub mod protocol;
pub mod rooms;
pub mod scoring;
pub mod skins;

pub use node::{Error, Result};

fn operation_error(error: anyhow::Error) -> Error {
    match error.downcast::<Error>() {
        Ok(error) => error,
        Err(error) => Error::Protocol(error.to_string()),
    }
}

pub mod bootstrap;
pub mod identity_bridge;
mod office_ai;
mod office_push;
mod office_workflows;
mod report_board;
pub mod runtime;

#[cfg(test)]
#[path = "../../union-core/tests/support/mod.rs"]
mod test_identity;
