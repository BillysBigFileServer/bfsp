pub use crate::crypto::*;

pub use crate::bfsp::files::*;
use crate::PrependLen;
use anyhow::{anyhow, Result};
pub use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};
use uuid::Uuid;

impl FileServerMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec().prepend_len()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes).map_err(|e| anyhow!("{e:?}"))
    }
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct ChunkID {
    pub id: u128,
}

impl TryFrom<&str> for ChunkID {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> anyhow::Result<Self> {
        Ok(Self {
            id: Uuid::from_str(value)
                .map_err(|err| anyhow!("Error deserializing ChunkID: {err}"))?
                .as_u128(),
        })
    }
}

impl Display for ChunkID {
    // converts it to a UUID, then displays it
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let uuid = Uuid::from_u128(self.id);
        f.write_str(&uuid.to_string())
    }
}

impl Serialize for ChunkID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let bytes = self.to_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChunkID {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 16]>::deserialize(deserializer)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl Debug for ChunkID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:#x}", self.id))
    }
}

impl ChunkID {
    pub const fn len() -> usize {
        16
    }
    pub fn to_bytes(&self) -> [u8; 16] {
        self.id.to_le_bytes()
    }
    pub fn from_bytes(buf: [u8; 16]) -> Self {
        Self {
            id: u128::from_le_bytes(buf),
        }
    }
}

impl ChunkID {
    pub fn new() -> Self {
        let uuid: Uuid = Uuid::new_v4();
        Self { id: uuid.as_u128() }
    }
}

// TODO: encrypt chunk metadata that isn't ID??
impl ChunkMetadata {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.encode_to_vec();
        let mut msg = (buf.len() as u32).to_le_bytes().to_vec();
        msg.append(&mut buf);
        msg
    }
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        Self::decode(buf).map_err(|e| anyhow!("{e:?}"))
    }
}

#[derive(Debug)]
pub struct AuthErr;

impl Display for AuthErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authenticaiton error")
    }
}

impl std::error::Error for AuthErr {}

#[derive(Debug)]
pub struct ChunkNotFound;

impl Display for ChunkNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Chunk not found")
    }
}

impl std::error::Error for ChunkNotFound {}
