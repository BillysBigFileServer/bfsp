use base64::{engine::general_purpose::URL_SAFE, Engine};
use std::io::Read;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use blake3::Hasher;
use chacha20poly1305::{aead::OsRng, AeadInPlace, Key, KeyInit, Nonce, XChaCha20Poly1305};

use crate::{files::ChunkMetadata, FileMetadata};

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
    pub fn new() -> Self {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        Self { key }
    }

    pub fn encrypt_chunk_in_place(
        &self,
        chunk: &mut Vec<u8>,
        chunk_meta: &ChunkMetadata,
    ) -> Result<()> {
        let key = XChaCha20Poly1305::new(&self.key);
        key.encrypt_in_place(
            chunk_meta.nonce.as_slice().into(),
            chunk_meta.id.as_slice(),
            chunk,
        )?;

        Ok(())
    }
    pub fn decrypt_chunk_in_place(
        &self,
        chunk: &mut Vec<u8>,
        chunk_meta: &ChunkMetadata,
    ) -> Result<()> {
        let key = XChaCha20Poly1305::new(&self.key);
        key.decrypt_in_place(
            chunk_meta.nonce.as_slice().into(),
            chunk_meta.id.as_slice(),
            chunk,
        )?;
        let comp_chunk = chunk.clone();
        let mut dec = ruzstd::StreamingDecoder::new(comp_chunk.as_slice()).unwrap();
        dec.read_to_end(chunk).unwrap();

        Ok(())
    }
    pub fn serialize(&self) -> String {
        URL_SAFE.encode(&self.key)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionNonce {
    pub(crate) nonce: [u8; 24],
}

impl EncryptionNonce {
    pub fn to_bytes(&self) -> [u8; 24] {
        self.nonce
    }
    pub fn serialize(&self) -> String {
        URL_SAFE.encode(&self.nonce)
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

#[derive(PartialEq)]
pub struct ChunkHash(pub(crate) blake3::Hash);

impl ChunkHash {
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

impl FileMetadata {
    /// Serialize the metadata to JSON,  compress it, encrypt the metadata, and serialize it again with base64
    pub fn encrypt_serialize(&self, enc_key: &EncryptionKey, nonce: EncryptionNonce) -> String {
        let mut compressed_json_bytes = {
            // simd_json is buggy when encoding for some reason?
            // TODO report the error
            let json = serde_json::to_string(self).unwrap();
            let json_bytes = json.as_bytes().to_vec();

            zstd::bulk::compress(&json_bytes, 15).unwrap()
        };

        let key = XChaCha20Poly1305::new(&enc_key.key);
        key.encrypt_in_place(
            nonce.to_bytes().as_slice().into(),
            b"",
            &mut compressed_json_bytes,
        )
        .unwrap();
        URL_SAFE.encode(&compressed_json_bytes)
    }

    pub fn decrypt_deserialize(
        enc_key: &EncryptionKey,
        nonce: EncryptionNonce,
        buffer: &str,
    ) -> Result<Self, String> {
        // Base64 decode
        let mut buffer = URL_SAFE
            .decode(buffer.as_bytes())
            .map_err(|err| format!("Error base64 decoding file metadata: {err}"))?;

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

        // JSON Deserialize
        Ok(simd_json::from_slice(&mut decompressed)
            .map_err(|err| format!("Error JSON deserializing file metadata: {err}"))?)
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
