pub use crate::bfsp::files::file_server_message::Authentication;
use anyhow::{anyhow, Result};
use prost::Message;

impl Authentication {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.encode_to_vec();
        let mut msg = (buf.len() as u32).to_le_bytes().to_vec();
        msg.append(&mut buf);

        msg
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes).map_err(|e| anyhow!("{e:?}"))
    }
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

impl CreateUserRequest {
    /// Returns true if the email is valid, false otherwise
    pub fn validate_email() -> bool {
        //FIXME
        true
    }
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
