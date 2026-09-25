//! Paper's built-in authenticated identity forwarding, shared by both hosting modes.
use crate::wire;
use anyhow::{Result, ensure};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::path::Path;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub uuid: uuid::Uuid,
    pub name: String,
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 16
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid player name"
    );
    Ok(())
}

pub fn read_secret(path: &Path) -> Result<String> {
    ensure!(
        std::fs::metadata(path)?.len() <= 258,
        "forwarding key too large"
    );
    let secret = std::fs::read_to_string(path)?;
    let secret = secret.trim();
    ensure!((32..=256).contains(&secret.len()), "invalid forwarding key");
    Ok(secret.to_owned())
}

pub fn encode(path: &Path, profile: &Profile) -> Result<Vec<u8>> {
    let secret = read_secret(path)?;
    let mut data = vec![];
    wire::varint(1, &mut data);
    wire::string("127.0.0.1", &mut data)?;
    data.extend(profile.uuid.as_bytes());
    wire::string(&profile.name, &mut data)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(&data);
    let mut result = mac.finalize().into_bytes().to_vec();
    result.extend(data);
    Ok(result)
}

/// Backend login negotiation shared by permanent and self-hosted rooms.
#[derive(Default)]
pub struct LoginNegotiation {
    forwarded: bool,
}
pub enum LoginStep {
    Forward,
    Compression(usize),
    Reply(wire::Packet),
    Ready,
}
impl LoginNegotiation {
    pub fn receive(
        &mut self,
        packet: &wire::Packet,
        compression: Option<usize>,
        profile: &Profile,
        payload: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<LoginStep> {
        use wire::Fields;
        match packet.id {
            wire::LOGIN_ENCRYPTION_REQUEST => {
                anyhow::bail!("backend encryption requested: configure Paper identity forwarding")
            }
            wire::LOGIN_COMPRESSION => {
                let mut fields = Fields::new(&packet.body);
                let threshold = usize::try_from(fields.int()?)?;
                fields.finish()?;
                ensure!(
                    compression.is_none() && threshold <= wire::MAX_PACKET,
                    "invalid compression negotiation"
                );
                Ok(LoginStep::Compression(threshold))
            }
            wire::LOGIN_CUSTOM_QUERY => {
                let mut fields = Fields::new(&packet.body);
                let transaction = fields.int()?;
                ensure!(
                    !self.forwarded && fields.text(128)? == "velocity:player_info",
                    "unsupported backend identity query"
                );
                ensure!(fields.remaining() == [4], "unsupported forwarding version");
                let mut body = Vec::new();
                wire::varint(transaction as u32, &mut body);
                body.push(1);
                body.extend(payload()?);
                self.forwarded = true;
                Ok(LoginStep::Reply(wire::Packet { id: 2, body }))
            }
            wire::LOGIN_FINISHED => {
                ensure!(self.forwarded, "backend did not verify identity forwarding");
                let mut fields = Fields::new(&packet.body);
                ensure!(
                    fields.bytes(16)? == profile.uuid.as_bytes()
                        && fields.text(16)? == profile.name,
                    "backend profile mismatch"
                );
                Ok(LoginStep::Ready)
            }
            wire::LOGIN_START | wire::LOGIN_COOKIE_REQUEST => Ok(LoginStep::Forward),
            _ => anyhow::bail!("unexpected backend login packet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwarding_requires_one_query_and_exact_backend_identity() -> Result<()> {
        let profile = Profile {
            uuid: uuid::Uuid::nil(),
            name: "Player".into(),
        };
        let mut login = LoginNegotiation::default();
        let mut success = profile.uuid.as_bytes().to_vec();
        wire::string(&profile.name, &mut success)?;
        let success = wire::Packet {
            id: 2,
            body: success,
        };
        assert!(
            login
                .receive(&success, None, &profile, || Ok(vec![]))
                .is_err()
        );
        let mut body = vec![0];
        wire::string("velocity:player_info", &mut body)?;
        body.push(4);
        let query = wire::Packet { id: 4, body };
        assert!(matches!(
            login.receive(&query, None, &profile, || Ok(vec![1]))?,
            LoginStep::Reply(_)
        ));
        assert!(
            login
                .receive(&query, None, &profile, || Ok(vec![]))
                .is_err()
        );
        let mut wrong = profile.clone();
        wrong.name = "Impostor".into();
        assert!(
            login
                .receive(&success, None, &wrong, || Ok(vec![]))
                .is_err()
        );
        assert!(matches!(
            login.receive(&success, None, &profile, || Ok(vec![]))?,
            LoginStep::Ready
        ));
        let compression = wire::Packet {
            id: 3,
            body: vec![0],
        };
        assert!(
            login
                .receive(&compression, Some(0), &profile, || Ok(vec![]))
                .is_err()
        );
        Ok(())
    }
}
