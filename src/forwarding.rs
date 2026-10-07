//! Paper's built-in authenticated identity forwarding, shared by both hosting modes.
use crate::protocol;
use anyhow::{Result, ensure};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::path::Path;

/// The Velocity `textures` profile property, the only property the gateway forwards.
/// Only the skin module can construct one, after checking what it describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Textures {
    value: String,
    signature: Option<String>,
}
impl Textures {
    pub(crate) fn new(value: String, signature: Option<String>) -> Self {
        Self { value, signature }
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub uuid: uuid::Uuid,
    pub name: String,
    /// Filled by the gateway after admission; never taken from configuration.
    #[serde(skip)]
    pub textures: Option<Textures>,
}

pub const TEXTURES_PROPERTY: &str = "textures";

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
    protocol::varint(1, &mut data);
    protocol::string("127.0.0.1", &mut data)?;
    data.extend(profile.uuid.as_bytes());
    protocol::string(&profile.name, &mut data)?;
    match &profile.textures {
        None => protocol::varint(0, &mut data),
        Some(textures) => {
            protocol::varint(1, &mut data);
            protocol::string(TEXTURES_PROPERTY, &mut data)?;
            protocol::string(textures.value(), &mut data)?;
            match textures.signature() {
                Some(signature) => {
                    data.push(1);
                    protocol::string(signature, &mut data)?;
                }
                None => data.push(0),
            }
        }
    }
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
    Reply(protocol::Packet),
    Ready,
}
impl LoginNegotiation {
    pub fn receive(
        &mut self,
        packet: &protocol::Packet,
        compression: Option<usize>,
        profile: &Profile,
        payload: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<LoginStep> {
        use protocol::Fields;
        match packet.id {
            protocol::LOGIN_ENCRYPTION_REQUEST => {
                anyhow::bail!("backend encryption requested: configure Paper identity forwarding")
            }
            protocol::LOGIN_COMPRESSION => {
                let mut fields = Fields::new(&packet.body);
                let threshold = usize::try_from(fields.int()?)?;
                fields.finish()?;
                ensure!(
                    compression.is_none() && threshold <= protocol::MAX_PACKET,
                    "invalid compression negotiation"
                );
                Ok(LoginStep::Compression(threshold))
            }
            protocol::LOGIN_CUSTOM_QUERY => {
                let mut fields = Fields::new(&packet.body);
                let transaction = fields.int()?;
                ensure!(
                    !self.forwarded && fields.text(128)? == "velocity:player_info",
                    "unsupported backend identity query"
                );
                ensure!(fields.remaining() == [4], "unsupported forwarding version");
                let mut body = Vec::new();
                protocol::varint(transaction as u32, &mut body);
                body.push(1);
                body.extend(payload()?);
                self.forwarded = true;
                Ok(LoginStep::Reply(protocol::Packet { id: 2, body }))
            }
            protocol::LOGIN_FINISHED => {
                ensure!(self.forwarded, "backend did not verify identity forwarding");
                let mut fields = Fields::new(&packet.body);
                ensure!(
                    fields.bytes(16)? == profile.uuid.as_bytes()
                        && fields.text(16)? == profile.name,
                    "backend profile mismatch"
                );
                Ok(LoginStep::Ready)
            }
            protocol::LOGIN_START | protocol::LOGIN_COOKIE_REQUEST => Ok(LoginStep::Forward),
            _ => anyhow::bail!("unexpected backend login packet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoded_identity_carries_typed_textures_after_the_name() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("secret");
        std::fs::write(&path, "s".repeat(32))?;
        for (textures, count) in [
            (None, 0),
            (
                Some(Textures::new("dmFsdWU=".into(), Some("sig".into()))),
                1,
            ),
            (Some(Textures::new("dmFsdWU=".into(), None)), 1),
        ] {
            let profile = Profile {
                uuid: uuid::Uuid::from_u128(9),
                name: "Alice".into(),
                textures: textures.clone(),
            };
            let encoded = encode(&path, &profile)?;
            let (mac, data) = encoded.split_at(32);
            let mut expected = Hmac::<Sha256>::new_from_slice("s".repeat(32).as_bytes())?;
            expected.update(data);
            expected.verify_slice(mac)?;
            let mut fields = protocol::Fields::new(data);
            assert_eq!(fields.int()?, 1);
            assert_eq!(fields.text(255)?, "127.0.0.1");
            assert_eq!(fields.bytes(16)?, profile.uuid.as_bytes());
            assert_eq!(fields.text(16)?, "Alice");
            assert_eq!(fields.int()?, count);
            if let Some(textures) = textures {
                assert_eq!(fields.text(64)?, TEXTURES_PROPERTY);
                assert_eq!(fields.text(32767)?, textures.value());
                let signed = fields.bytes(1)?[0];
                assert_eq!(signed == 1, textures.signature().is_some());
                if let Some(signature) = textures.signature() {
                    assert_eq!(fields.text(32767)?, signature);
                }
            }
            fields.finish()?;
        }
        Ok(())
    }
    #[test]
    fn forwarding_requires_one_query_and_exact_backend_identity() -> Result<()> {
        let profile = Profile {
            uuid: uuid::Uuid::nil(),
            name: "Player".into(),
            textures: None,
        };
        let mut login = LoginNegotiation::default();
        let mut success = profile.uuid.as_bytes().to_vec();
        protocol::string(&profile.name, &mut success)?;
        let success = protocol::Packet {
            id: 2,
            body: success,
        };
        assert!(
            login
                .receive(&success, None, &profile, || Ok(vec![]))
                .is_err()
        );
        let mut body = vec![0];
        protocol::string("velocity:player_info", &mut body)?;
        body.push(4);
        let query = protocol::Packet { id: 4, body };
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
        let compression = protocol::Packet {
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
