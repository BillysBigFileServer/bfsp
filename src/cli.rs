use anyhow::{anyhow, Result};
use blake3::Hasher;
use std::{
    collections::HashMap,
    io::{Seek, SeekFrom},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

pub use crate::bfsp::files::ChunkMetadata;
use crate::{ChunkHash, ChunkID, EncryptionKey, EncryptionNonce, FileHash};
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct FileHeader {
    pub hash: FileHash,
    pub chunk_size: u32,
    pub chunks: HashMap<ChunkID, ChunkMetadata>,
    pub chunk_indices: HashMap<ChunkID, i64>,
}

impl FileHeader {
    pub fn total_file_size(&self) -> u64 {
        self.chunks.values().map(|chunk| chunk.size as u64).sum()
    }
}

impl FileHeader {
    /// Random file ID
    pub async fn from_file(file: &mut File) -> Result<Self> {
        file.rewind().await?;

        let metadata = file.metadata().await?;
        let size = metadata.len();
        let chunk_size = match size {
            // 8KiB for anything less than 256 KiB
            0..=262_144 => 8192,
            // 64KiB for anything up to 8MiB
            262_145..=8388608 => 65536,
            // 8MiB for anything higher
            _ => 8388608,
        };

        let mut total_file_hasher = Hasher::new();
        // Use parallel hashing for data larger than 256KiB
        let use_parallel_chunk = use_parallel_hasher(chunk_size);

        let mut chunk_buf = vec![0; chunk_size];
        let mut chunk_buf_index = 0;

        let mut chunks = HashMap::new();
        let mut chunk_indices = HashMap::new();
        let mut chunk_index = 0;

        loop {
            // First, read into the buffer until it's full, or we hit an EOF
            let eof = loop {
                if chunk_buf_index == chunk_buf.len() {
                    break false;
                }
                match file.read(&mut chunk_buf[chunk_buf_index..]).await {
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

            let mut chunk_hasher = Hasher::new();
            // Next, take the hash of the chunk that was read
            match use_parallel_chunk {
                true => {
                    total_file_hasher.update_rayon(chunk_buf);
                    chunk_hasher.update_rayon(chunk_buf);
                }
                false => {
                    total_file_hasher.update(chunk_buf);
                    chunk_hasher.update(chunk_buf);
                }
            };

            let chunk_hash: ChunkHash = chunk_hasher.finalize().into();
            let chunk_id = ChunkID::new(&chunk_hash);
            let nonce = EncryptionNonce::new();

            // Finally, insert some chunk metadata
            chunks.insert(
                chunk_id,
                ChunkMetadata {
                    id: chunk_id.to_bytes().to_vec(),
                    indice: chunk_index,
                    hash: chunk_hash.to_bytes().to_vec(),
                    size: chunk_buf.len() as u32,
                    nonce: nonce.to_bytes().to_vec(),
                },
            );
            chunk_indices.insert(chunk_id, chunk_index);

            chunk_index += 1;

            if eof {
                break;
            }
            chunk_buf_index = 0;
        }

        file.rewind().await?;

        Ok(Self {
            hash: total_file_hasher.finalize().into(),
            chunk_size: chunk_size as u32,
            chunks,
            chunk_indices,
        })
    }
}

pub fn compressed_encrypted_chunks_from_file(
    file_header: &FileHeader,
    file: &mut std::fs::File,
    chunk_ids: &[ChunkID],
    key: &EncryptionKey,
) -> Result<Vec<(ChunkMetadata, Vec<u8>)>> {
    use std::io::Read;

    let chunk_infos: Vec<(ChunkMetadata, Vec<u8>, EncryptionKey)> = chunk_ids
        .iter()
        .map(|chunk_id| {
            let chunk_meta = file_header
                .chunks
                .get(&chunk_id)
                .ok_or_else(|| anyhow!("Chunk {chunk_id} not found in chunks"))?;

            let chunk_indice = *file_header
                .chunk_indices
                .get(&chunk_id)
                .ok_or_else(|| anyhow!("Chunk {chunk_id} not found in chunk_indices"))?;

            let byte_index = chunk_indice as u64 * file_header.chunk_size as u64;

            file.seek(SeekFrom::Start(byte_index))?;

            let mut buf = Vec::with_capacity(chunk_meta.size as usize);
            file.take(chunk_meta.size as u64).read_to_end(&mut buf)?;

            // We have to include the key to be able to do this parallel
            Ok((chunk_meta.clone(), buf, key.clone()))
        })
        .collect::<Result<Vec<_>>>()?;

    chunk_infos
        .into_par_iter()
        .map(
            move |(chunk_meta, buf, key): (ChunkMetadata, Vec<u8>, EncryptionKey)| {
                Ok((
                    chunk_meta.clone(),
                    compress_and_encrypt(chunk_meta, buf, &key)?,
                ))
            },
        )
        .collect::<Result<_>>()
}

fn compress_and_encrypt(
    chunk_meta: ChunkMetadata,
    buf: Vec<u8>,
    key: &EncryptionKey,
) -> Result<Vec<u8>> {
    println!("Size before compression: {}KB", buf.len());
    let mut buf = zstd::bulk::compress(&buf, 15)?;
    key.encrypt_chunk_in_place(&mut buf, &chunk_meta)?;

    println!("Size after compression + encryption: {}KB", buf.len());
    Ok(buf)
}

pub const fn use_parallel_hasher(size: usize) -> bool {
    size > 262_144
}
