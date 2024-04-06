/// Billy's file sync protocol
#[cfg(test)]
mod test;

mod bfsp {
    pub(crate) mod files {
        include!(concat!(env!("OUT_DIR"), "/bfsp.files.rs"));
    }

    pub mod ipc {
        include!(concat!(env!("OUT_DIR"), "/bfsp.ipc.rs"));
    }
}

pub use bfsp::*;
pub use prost::Message;

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;

pub mod crypto;
pub mod file;
pub use file::*;

pub mod auth;

pub trait PrependLen {
    fn prepend_len(self) -> Self;
}
impl PrependLen for Vec<u8> {
    fn prepend_len(mut self) -> Self {
        let len = self.len();

        let mut len_bytes = (len as u32).to_le_bytes().to_vec();
        len_bytes.append(&mut self);
        len_bytes
    }
}
