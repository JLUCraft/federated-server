//! Minecraft 26.3 framing; IDs pinned from the official server data report.
use anyhow::{Result, bail, ensure};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_MC_PORT: u16 = 25565;
pub const CONFIGURATION_TRANSFER: i32 = 12;
pub const VERSION: i32 = 777;
pub const MAX_FRAME: usize = 2_097_151;
pub const MAX_PACKET: usize = 8_388_608;
pub const PLAY_TRANSFER: i32 = 132;
pub const PLAY_KEEPALIVE: i32 = 45;
pub const PLAY_KEEPALIVE_REPLY: i32 = 28;
pub const PLAY_RECONFIGURE: i32 = 120;
pub const PLAY_RECONFIGURE_ACK: i32 = 16;
// Login-state IDs from the same official report; clientbound unless noted.
pub const LOGIN_START: i32 = 0;
pub const LOGIN_ENCRYPTION_REQUEST: i32 = 1;
pub const LOGIN_FINISHED: i32 = 2;
pub const LOGIN_COMPRESSION: i32 = 3;
pub const LOGIN_CUSTOM_QUERY: i32 = 4;
pub const LOGIN_COOKIE_REQUEST: i32 = 5;

pub fn varint(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let next = (value & 0x7f) as u8;
        value >>= 7;
        out.push(next | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}
pub fn string(value: &str, out: &mut Vec<u8>) -> Result<()> {
    ensure!(value.len() <= 32767, "string too large");
    varint(u32::try_from(value.len())?, out);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
pub struct Fields<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Fields<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub fn int(&mut self) -> Result<i32> {
        let mut value = 0u32;
        for shift in (0..35).step_by(7) {
            let byte = self.bytes(1)?[0];
            ensure!(shift < 28 || byte & 0xf0 == 0, "varint overflow");
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value as i32);
            }
        }
        bail!("varint too long")
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("length overflow"))?;
        ensure!(end <= self.bytes.len(), "truncated packet");
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }
    pub fn text(&mut self, max: usize) -> Result<&'a str> {
        let n = usize::try_from(self.int()?)?;
        ensure!(n <= max, "string too large");
        Ok(std::str::from_utf8(self.bytes(n)?)?)
    }
    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
    pub fn finish(&self) -> Result<()> {
        ensure!(self.remaining().is_empty(), "unexpected trailing bytes");
        Ok(())
    }
}
#[derive(Debug)]
pub struct Packet {
    pub id: i32,
    pub body: Vec<u8>,
}
impl Packet {
    pub fn decode(raw: &[u8], threshold: Option<usize>) -> Result<Self> {
        let data = if let Some(threshold) = threshold {
            let mut fields = Fields::new(raw);
            let length = usize::try_from(fields.int()?)?;
            if length == 0 {
                ensure!(
                    fields.remaining().len() < threshold,
                    "uncompressed packet above threshold"
                );
                fields.remaining().to_vec()
            } else {
                ensure!(
                    (threshold..=MAX_PACKET).contains(&length),
                    "invalid decompressed length"
                );
                let compressed = fields.remaining();
                let mut decoder = ZlibDecoder::new(compressed);
                let mut decoded = Vec::with_capacity(length.min(65536));
                decoder
                    .by_ref()
                    .take((MAX_PACKET + 1) as u64)
                    .read_to_end(&mut decoded)?;
                ensure!(
                    decoded.len() == length && decoder.total_in() == compressed.len() as u64,
                    "invalid compressed packet"
                );
                decoded
            }
        } else {
            raw.to_vec()
        };
        ensure!(data.len() <= MAX_PACKET, "packet too large");
        let mut fields = Fields::new(&data);
        let id = fields.int()?;
        ensure!(id >= 0, "invalid packet id");
        Ok(Self {
            id,
            body: fields.remaining().to_vec(),
        })
    }
    pub fn encode(&self, threshold: Option<usize>) -> Result<Vec<u8>> {
        ensure!(self.id >= 0, "invalid packet id");
        let mut data = Vec::new();
        varint(self.id as u32, &mut data);
        data.extend_from_slice(&self.body);
        ensure!(data.len() <= MAX_PACKET, "packet too large");
        let raw = if let Some(threshold) = threshold {
            let mut out = Vec::new();
            if data.len() >= threshold {
                varint(u32::try_from(data.len())?, &mut out);
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
                encoder.write_all(&data)?;
                out.extend(encoder.finish()?);
            } else {
                varint(0, &mut out);
                out.extend(data);
            }
            out
        } else {
            data
        };
        ensure!(raw.len() <= MAX_FRAME, "encoded frame too large");
        Ok(raw)
    }
}
/// Read complete raw frames in a dedicated task: cancelling read_exact mid-frame
/// would corrupt the stream when routing updates race with network input.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut length = 0usize;
    for shift in [0, 7, 14] {
        let byte = reader.read_u8().await?;
        length |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            ensure!((1..=MAX_FRAME).contains(&length), "invalid frame length");
            let mut raw = vec![0; length];
            reader.read_exact(&mut raw).await?;
            return Ok(raw);
        }
    }
    bail!("frame length exceeds 3-byte varint")
}
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, raw: &[u8]) -> Result<()> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_FRAME,
        "invalid frame length"
    );
    let mut header = Vec::new();
    varint(u32::try_from(raw.len())?, &mut header);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        writer.write_all(&header).await?;
        writer.write_all(raw).await?;
        writer.flush().await
    })
    .await??;
    Ok(())
}
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: Packet,
    threshold: Option<usize>,
) -> Result<()> {
    write_frame(writer, &packet.encode(threshold)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compression_boundaries_and_truncation() -> Result<()> {
        for threshold in [None, Some(0), Some(256)] {
            for size in [0, 32, 256, 4096] {
                let p = Packet {
                    id: 132,
                    body: vec![42; size],
                };
                let decoded = Packet::decode(&p.encode(threshold)?, threshold)?;
                assert_eq!(decoded.id, p.id);
                assert_eq!(decoded.body, p.body);
            }
        }
        assert!(Fields::new(&[255, 255, 255, 255, 127]).int().is_err());
        assert!(Packet::decode(&[128], None).is_err());
        assert!(Packet::decode(&[0, 1, 2], Some(1)).is_err());
        let mut data = vec![];
        varint((MAX_PACKET + 1) as u32, &mut data);
        data.extend([1, 2]);
        assert!(Packet::decode(&data, Some(256)).is_err());
        Ok(())
    }
    #[test]
    fn packet_ids_match_official_report() -> Result<()> {
        let report: serde_json::Value =
            serde_json::from_str(include_str!("../protocol/26.3-packets.json"))?;
        for (direction, name, id) in [
            ("clientbound", "transfer", PLAY_TRANSFER),
            ("clientbound", "keep_alive", PLAY_KEEPALIVE),
            ("serverbound", "keep_alive", PLAY_KEEPALIVE_REPLY),
            ("clientbound", "start_configuration", PLAY_RECONFIGURE),
            (
                "serverbound",
                "configuration_acknowledged",
                PLAY_RECONFIGURE_ACK,
            ),
        ] {
            assert_eq!(
                report["play"][direction][format!("minecraft:{name}")]["protocol_id"],
                id
            );
        }
        Ok(())
    }
}
