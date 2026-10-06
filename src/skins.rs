//! Player textures for identity forwarding, fetched from the province's skin station.
//!
//! There is exactly one skin station. Textures are cosmetic: any failure yields no textures
//! and never blocks a login.
use crate::forwarding::{TEXTURES_PROPERTY, Textures};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};

const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TEXTURES_VALUE_BYTES: usize = 16 * 1024;

/// The skin station's bare origin. Textures must be hosted on it.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct SkinSite(Url);

/// A bare `https://` origin; plain `http://` only for loopback development.
fn parse_origin(origin: &str) -> Result<Url> {
    let url = Url::parse(origin)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "skin site must use https"
    );
    ensure!(
        url.host_str().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty(),
        "skin site must be a bare origin"
    );
    Ok(url)
}

impl TryFrom<String> for SkinSite {
    type Error = anyhow::Error;
    fn try_from(origin: String) -> Result<Self> {
        parse_origin(&origin)
            .map(Self)
            .map_err(|e| anyhow::anyhow!("skin site {origin}: {e}"))
    }
}

#[derive(Deserialize)]
struct RemoteProfile {
    id: uuid::Uuid,
    name: String,
    properties: Vec<RemoteProperty>,
}
#[derive(Deserialize)]
struct RemoteProperty {
    name: String,
    value: String,
    signature: Option<String>,
}
#[derive(Deserialize)]
struct TexturesValue {
    #[serde(rename = "profileId")]
    profile_id: uuid::Uuid,
    textures: BTreeMap<TextureKind, TextureRef>,
}
#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum TextureKind {
    #[serde(rename = "SKIN")]
    Skin,
    #[serde(rename = "CAPE")]
    Cape,
}
#[derive(Deserialize)]
struct TextureRef {
    url: String,
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= MAX_RESPONSE_BYTES,
            "skin site response too large"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl SkinSite {
    async fn fetch(&self, uuid: uuid::Uuid, name: &str) -> Result<Option<Textures>> {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()?;
        let url = self.0.join(&format!(
            "sessionserver/session/minecraft/profile/{}",
            uuid.simple()
        ))?;
        let response = client
            .get(url)
            .query(&[("unsigned", "false")])
            .send()
            .await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        ensure!(response.status().is_success(), "skin site rejected request");
        let profile: RemoteProfile = serde_json::from_slice(&read_limited(response).await?)?;
        ensure!(
            profile.id == uuid && profile.name == name,
            "skin site returned a different profile"
        );
        let Some(property) = profile
            .properties
            .into_iter()
            .find(|p| p.name == TEXTURES_PROPERTY)
        else {
            return Ok(None);
        };
        ensure!(
            property.value.len() <= MAX_TEXTURES_VALUE_BYTES,
            "textures property too large"
        );
        let value: TexturesValue = serde_json::from_slice(&STANDARD.decode(&property.value)?)?;
        ensure!(
            value.profile_id == uuid,
            "textures describe a different profile"
        );
        for texture in value.textures.values() {
            ensure!(
                Url::parse(&texture.url)?.origin() == self.0.origin(),
                "texture hosted outside the skin site"
            );
        }
        Ok(Some(Textures::new(property.value, property.signature)))
    }

    /// The player's `textures` property, or none when the station lacks it or misbehaves.
    pub async fn textures(&self, uuid: uuid::Uuid, name: &str) -> Option<Textures> {
        match self.fetch(uuid, name).await {
            Ok(textures) => textures,
            Err(error) => {
                tracing::debug!(%error, "skin site lookup failed");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Path, http::StatusCode as Status, routing::get};

    fn profile(id: &str, name: &str, texture_url: &str) -> serde_json::Value {
        let value = STANDARD.encode(
            serde_json::json!({
                "profileId": id,
                "textures": {"SKIN": {"url": texture_url}}
            })
            .to_string(),
        );
        serde_json::json!({
            "id": id,
            "name": name,
            "properties": [
                {"name": "uploadableTextures", "value": "skin,cape", "signature": null},
                {"name": "textures", "value": value, "signature": "sig"}
            ]
        })
    }
    /// A station serving `payload(origin, id)` for one profile and 204 otherwise.
    async fn station(known: uuid::Uuid, payload: fn(&str, &str) -> serde_json::Value) -> SkinSite {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let served = origin.clone();
        let router = Router::new().route(
            "/sessionserver/session/minecraft/profile/{id}",
            get(move |Path(id): Path<String>| {
                let served = served.clone();
                async move {
                    if id == known.simple().to_string() {
                        Ok(Json(payload(&served, &id)))
                    } else {
                        Err(Status::NO_CONTENT)
                    }
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await });
        SkinSite::try_from(origin).unwrap()
    }

    #[tokio::test]
    async fn textures_come_from_the_station_that_knows_the_profile() {
        let known = uuid::Uuid::from_u128(7);
        let site = station(known, |origin, id| {
            profile(id, "Alice", &format!("{origin}/textures/abc"))
        })
        .await;
        let textures = site.textures(known, "Alice").await.unwrap();
        assert_eq!(textures.signature(), Some("sig"));
        assert!(!textures.value().is_empty());
        assert!(
            site.textures(uuid::Uuid::from_u128(8), "Bob")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn mismatched_or_foreign_textures_are_dropped() {
        let known = uuid::Uuid::from_u128(7);
        let foreign = station(known, |_, id| {
            profile(id, "Alice", "https://elsewhere.example/textures/abc")
        })
        .await;
        assert!(foreign.textures(known, "Alice").await.is_none());
        let renamed = station(known, |origin, id| {
            profile(id, "Impostor", &format!("{origin}/textures/abc"))
        })
        .await;
        assert!(renamed.textures(known, "Alice").await.is_none());
    }

    #[test]
    fn the_origin_must_be_https_or_a_loopback_bare_origin() {
        for good in ["https://skin.example.test", "http://127.0.0.1:8080"] {
            assert!(SkinSite::try_from(good.to_owned()).is_ok(), "{good}");
        }
        for bad in [
            "http://skin.example.test",
            "https://skin.example.test/path",
            "https://user@skin.example.test",
            "https://skin.example.test/?q=1",
            "not a url",
        ] {
            assert!(SkinSite::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}
