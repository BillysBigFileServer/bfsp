include!(concat!(env!("OUT_DIR"), "/bfsp.internal.rs"));
use chacha20poly1305::{aead::AeadMutInPlace, XChaCha20Poly1305};
use prost::Message;

pub fn encrypt_internal_message(
    mut key: XChaCha20Poly1305,
    nonce: Vec<u8>,
    message: InternalFileServerMessage,
) -> EncryptedInternalFileServerMessage {
    let mut message_bytes = message.encode_to_vec();
    key.encrypt_in_place(nonce.as_slice().into(), b"", &mut message_bytes)
        .unwrap();

    EncryptedInternalFileServerMessage {
        nonce,
        enc_message: message_bytes,
    }
}

pub fn decrypt_internal_message(
    mut key: XChaCha20Poly1305,
    enc_message: EncryptedInternalFileServerMessage,
) -> InternalFileServerMessage {
    let mut message_bytes = enc_message.enc_message;
    key.decrypt_in_place(enc_message.nonce.as_slice().into(), b"", &mut message_bytes)
        .unwrap();

    InternalFileServerMessage::decode(message_bytes.as_slice()).unwrap()
}
