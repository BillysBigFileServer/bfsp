pub use crate::bfsp::files::file_server_message::Authentication;
use anyhow::{anyhow, Result};
use macaroon::ByteString;
use prost::Message;
use regex::Regex;

#[derive(Clone)]
pub struct EmailCaveat {
    pub email: String,
}

impl From<EmailCaveat> for ByteString {
    fn from(caveat: EmailCaveat) -> Self {
        caveat.to_string().into()
    }
}

impl ToString for EmailCaveat {
    fn to_string(&self) -> String {
        format!("email = {}", self.email)
    }
}

impl TryFrom<ByteString> for EmailCaveat {
    type Error = anyhow::Error;

    fn try_from(value: ByteString) -> Result<Self> {
        let value: String = String::from_utf8(value.0)?;

        let re = Regex::new("email = (?<email>[a-zA-Z0-9_-]*)")?;
        let Some(caps) = re.captures(&value) else {
            return Err(anyhow!("invalid email caveat"));
        };
        let email = &caps["email"];

        Ok(Self {
            email: email.to_string(),
        })
    }
}

#[derive(Clone)]
pub struct ExpirationCaveat {
    pub expiration: u64,
}

impl Into<ByteString> for ExpirationCaveat {
    fn into(self) -> ByteString {
        self.to_string().into()
    }
}

impl ToString for ExpirationCaveat {
    fn to_string(&self) -> String {
        format!("expires = {}", self.expiration)
    }
}

impl TryFrom<&ByteString> for ExpirationCaveat {
    type Error = anyhow::Error;

    fn try_from(value: &ByteString) -> Result<Self> {
        let value: String = String::from_utf8(value.0.clone())?;

        let re = Regex::new("expires = (?<expires>[a-zA-Z0-9_-]*)")?;
        let Some(caps) = re.captures(&value) else {
            return Err(anyhow!("invalid expiration caveat"));
        };
        let expiration = &caps["expires"].to_string();
        let expiration: u64 = expiration.parse()?;

        Ok(Self { expiration })
    }
}

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
