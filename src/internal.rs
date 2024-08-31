include!(concat!(env!("OUT_DIR"), "/bfsp.internal.rs"));
use std::error::Error;

use chacha20poly1305::{aead::Aead, XChaCha20Poly1305};
use prost::Message;

pub fn encrypt_internal_message(
    key: XChaCha20Poly1305,
    nonce: Vec<u8>,
    message: InternalFileServerMessage,
) -> EncryptedInternalFileServerMessage {
    let enc_message = key
        .encrypt(nonce.as_slice().into(), message.encode_to_vec().as_slice())
        .unwrap();

    EncryptedInternalFileServerMessage { nonce, enc_message }
}

pub fn decrypt_internal_message(
    key: XChaCha20Poly1305,
    enc_message: EncryptedInternalFileServerMessage,
) -> InternalFileServerMessage {
    let decrypted_message = key
        .decrypt(
            enc_message.nonce.as_slice().into(),
            enc_message.enc_message.as_slice(),
        )
        .unwrap();

    InternalFileServerMessage::decode(decrypted_message.as_slice()).unwrap()
}
