use argon2::password_hash::{PasswordHasher, SaltString};

use base64::{engine::general_purpose::URL_SAFE, Engine};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{io::Read, str::FromStr};
use uuid::Uuid;

use anyhow::{anyhow, Result};
use blake3::Hasher;
use chacha20poly1305::{AeadInPlace, Key, KeyInit, XChaCha20Poly1305};

use crate::{files::ChunkMetadata, FileMetadata};

const COMPRESSION_LEVEL: i32 = 1;

#[derive(Clone)]
pub struct EncryptionKey {
    pub(crate) key: Key,
}

impl TryFrom<Vec<u8>> for EncryptionKey {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        let mut key: Key = [0; 32].into();
        key.copy_from_slice(&value);

        Ok(Self { key })
    }
}

impl TryFrom<&[u8]> for EncryptionKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let mut key: Key = [0; 32].into();
        key.copy_from_slice(value);

        Ok(Self { key })
    }
}

impl TryFrom<&str> for EncryptionKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let bytes: Vec<u8> = URL_SAFE.decode(value)?;
        bytes.try_into()
    }
}

impl Into<Vec<u8>> for EncryptionKey {
    fn into(self) -> Vec<u8> {
        self.key.to_vec()
    }
}

impl EncryptionKey {
    pub fn new(password: &str) -> Self {
        let salt: SaltString = SaltString::from_b64("g8QqYqhXxwJj037KswzK3g").unwrap();
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .hash
            .unwrap();
        let password_hash_bytes = password_hash.as_bytes();
        // We need to make the password hash a fixed length, so we use blake3
        let mut hasher = blake3::Hasher::new();
        hasher.update(password_hash_bytes);
        let key = hasher.finalize();

        // blake3 has a 32 byte output, which is the same as the key size for XChaCha20Poly1305 :)
        let key: Key = *Key::from_slice(key.as_bytes());
        Self { key }
    }

    /// Generates a new encryption key based on the master key and the hash of a file
    pub fn derive_key(&self, file_id: &Uuid) -> Self {
        let mut new_key_bytes = self.key.to_vec();
        new_key_bytes.extend_from_slice(file_id.as_bytes());

        let new_key_bytes_hash = blake3::hash(&new_key_bytes);
        let key: Key = *Key::from_slice(new_key_bytes_hash.as_bytes());
        Self { key }
    }

    pub fn compress_encrypt_chunk_in_place(
        &self,
        chunk: &mut Vec<u8>,
        chunk_meta: &ChunkMetadata,
    ) -> Result<()> {
        let mut compressed_chunk = zstd::bulk::compress(chunk, COMPRESSION_LEVEL)?;
        let key = XChaCha20Poly1305::new(&self.key);
        key.encrypt_in_place(
            chunk_meta.nonce.as_slice().into(),
            chunk_meta.id.as_bytes(),
            &mut compressed_chunk,
        )?;
        *chunk = compressed_chunk;

        Ok(())
    }
    pub fn decrypt_decompress_chunk_in_place(
        &self,
        chunk: &mut Vec<u8>,
        chunk_meta: &ChunkMetadata,
    ) -> Result<()> {
        let key = XChaCha20Poly1305::new(&self.key);
        key.decrypt_in_place(
            chunk_meta.nonce.as_slice().try_into()?,
            chunk_meta.id.as_bytes(),
            chunk,
        )?;
        let comp_chunk = chunk.clone();
        let mut dec = ruzstd::StreamingDecoder::new(comp_chunk.as_slice()).map_err(|err| {
            anyhow!(
                "Error creating ZSTD decompressor for chunk {}: {err}",
                chunk_meta.id
            )
        })?;
        *chunk = Vec::new();
        dec.read_to_end(chunk)
            .map_err(|err| anyhow!("Error decompressing chunk {}: {err}", chunk_meta.id))?;

        Ok(())
    }
    pub fn serialize(&self) -> String {
        URL_SAFE.encode(&self.key)
    }

    pub fn deserialize(b64: &str) -> Self {
        let key = *Key::from_slice(URL_SAFE.decode(b64).unwrap().as_slice());
        Self { key }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionNonce {
    pub(crate) nonce: [u8; 24],
}

impl EncryptionNonce {
    pub fn len() -> usize {
        24
    }
}

impl EncryptionNonce {
    pub fn to_bytes(&self) -> [u8; 24] {
        self.nonce
    }
    pub fn serialize(&self) -> String {
        URL_SAFE.encode(&self.nonce)
    }
}

impl TryFrom<&[u8]> for EncryptionNonce {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let mut nonce: [u8; 24] = [0; 24];
        nonce.copy_from_slice(value);
        Ok(Self { nonce })
    }
}

impl TryFrom<Vec<u8>> for EncryptionNonce {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Ok(Self {
            nonce: value.try_into().map_err(|e| anyhow!("{e:?}"))?,
        })
    }
}

impl TryFrom<&str> for EncryptionNonce {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let value: Vec<u8> = URL_SAFE.decode(&value)?;
        let value: Result<Self> = value.try_into();
        value
    }
}

impl EncryptionNonce {
    pub fn new() -> Self {
        Self {
            nonce: rand::random(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ChunkHash(pub(crate) blake3::Hash);

impl Serialize for ChunkHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_bytes().serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for ChunkHash {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; blake3::OUT_LEN] = Deserialize::deserialize(deserializer)?;
        Ok(Self(blake3::Hash::from_bytes(bytes)))
    }
}

impl ChunkHash {
    pub const fn len() -> usize {
        blake3::OUT_LEN
    }
    pub fn to_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn from_bytes(buf: [u8; blake3::OUT_LEN]) -> Self {
        Self(blake3::Hash::from_bytes(buf))
    }
}

impl From<blake3::Hash> for ChunkHash {
    fn from(value: blake3::Hash) -> Self {
        Self(value)
    }
}

impl ToString for ChunkHash {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl TryFrom<&[u8]> for ChunkHash {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> anyhow::Result<Self> {
        let slice: &[u8; blake3::OUT_LEN] = value.try_into()?;
        Ok(Self(blake3::Hash::from_bytes(*slice)))
    }
}

impl TryFrom<Vec<u8>> for ChunkHash {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> anyhow::Result<Self> {
        value.as_slice().try_into()
    }
}

impl Into<[u8; blake3::OUT_LEN]> for ChunkHash {
    fn into(self) -> [u8; blake3::OUT_LEN] {
        *self.0.as_bytes()
    }
}

impl TryFrom<String> for ChunkHash {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Ok(Self(blake3::Hash::from_str(&value)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FileHash(pub(crate) blake3::Hash);

impl std::fmt::Display for FileHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl From<blake3::Hash> for FileHash {
    fn from(value: blake3::Hash) -> Self {
        Self(value)
    }
}

impl TryFrom<String> for FileHash {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(Self(blake3::Hash::from_str(&value)?))
    }
}

impl TryFrom<&[u8]> for FileHash {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> anyhow::Result<Self> {
        let slice: &[u8; blake3::OUT_LEN] = value.try_into().map_err(|_err| {
            anyhow!(
                "Could not convert slice of length {} to [u8; 32]",
                value.len()
            )
        })?;
        Ok(Self(blake3::Hash::from_bytes(*slice)))
    }
}

impl TryFrom<Vec<u8>> for FileHash {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> anyhow::Result<Self> {
        value.as_slice().try_into()
    }
}

impl ChunkMetadata {
    pub fn encode_base64(&self) -> String {
        URL_SAFE.encode(&self.encode_to_vec())
    }
}

impl FileMetadata {
    /// Serialize the metadata to JSON,  compress it, encrypt the metadata, and serialize it again with base64
    pub fn encrypt_serialize(
        &self,
        enc_key: &EncryptionKey,
        nonce: EncryptionNonce,
    ) -> Result<Vec<u8>, String> {
        let bytes = self.encode_to_vec();
        let mut compressed_bytes = zstd::bulk::compress(&bytes, COMPRESSION_LEVEL)
            .map_err(|err| format!("Error compressing file metadata: {err}"))?;

        let key = XChaCha20Poly1305::new(&enc_key.key);
        key.encrypt_in_place(
            nonce.to_bytes().as_slice().into(),
            b"",
            &mut compressed_bytes,
        )
        .map_err(|err| format!("Error encrypting file metadata: {err}"))?;

        Ok(compressed_bytes)
    }

    pub fn decrypt_deserialize(
        enc_key: &EncryptionKey,
        nonce: EncryptionNonce,
        mut buffer: Vec<u8>,
    ) -> Result<Self, String> {
        // Decrypt
        let key = XChaCha20Poly1305::new(&enc_key.key);
        key.decrypt_in_place(nonce.to_bytes().as_slice().into(), b"", &mut buffer)
            .map_err(|err| format!("Error decrypting file metadata: {err}"))?;

        // Decompress
        let mut dec = ruzstd::StreamingDecoder::new(buffer.as_slice())
            .map_err(|err| format!("Error creating ZSTD decompressor for file metadata: {err}"))?;
        let mut decompressed = Vec::new();
        dec.read_to_end(&mut decompressed)
            .map_err(|err| format!("Error decompressing file metadata: {err}"))?;

        let metadata = FileMetadata::decode(decompressed.as_slice())
            .map_err(|err| format!("Error deserializing file metadata: {err}"))?;
        Ok(metadata)
    }
}

pub fn hash_file(file: &mut std::fs::File) -> Result<FileHash> {
    // 8MB
    let chunk_size = 8388608 * 8;

    let mut total_file_hasher = Hasher::new();
    let mut chunk_buf = vec![0; chunk_size];
    let mut chunk_buf_index = 0;

    loop {
        // First, read into the buffer until it's full, or we hit an EOF
        let eof = loop {
            if chunk_buf_index == chunk_buf.len() {
                break false;
            }
            match file.read(&mut chunk_buf[chunk_buf_index..]) {
                Ok(num_bytes_read) => match num_bytes_read {
                    0 => break true,
                    b => chunk_buf_index += b,
                },
                Err(err) => match err.kind() {
                    std::io::ErrorKind::UnexpectedEof => break true,
                    _ => return anyhow::Result::Err(err.into()),
                },
            };
        };

        let chunk_buf = &chunk_buf[..chunk_buf_index];

        total_file_hasher.update_rayon(chunk_buf);

        if eof {
            break;
        }

        chunk_buf_index = 0;
    }

    Ok(FileHash(total_file_hasher.finalize()))
}

pub fn hash_chunk(chunk: &[u8]) -> ChunkHash {
    let mut hasher = Hasher::new();
    hasher.update(chunk);
    hasher.finalize().into()
}

pub fn parallel_hash_chunk(chunk: &[u8]) -> ChunkHash {
    let mut hasher = Hasher::new();
    hasher.update(chunk);
    hasher.finalize().into()
}

pub fn hash_password(password: &str) -> String {
    let argon2 = argon2::Argon2::default();
    let salt: SaltString = SaltString::from_b64("g8QqYqhXxwJj037KswzK3g").unwrap();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn base64_encode(data: &[u8]) -> String {
    URL_SAFE.encode(data)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE.decode(data)?)
}
