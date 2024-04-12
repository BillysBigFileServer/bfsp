use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs::{self, File};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub token: Option<String>,
    pub enc_key: Option<String>,
}

#[derive(Error, Debug)]
pub enum DeserializeConfigError {
    #[error("Failed to open config file")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse config file")]
    TomlError(#[from] toml::de::Error),
}

pub async fn config_from_file(config_path: &Path) -> Result<Config, DeserializeConfigError> {
    if !fs::try_exists(config_path).await? {
        fs::create_dir_all(config_path.parent().unwrap()).await?;

        println!("Creating config file at {}", config_path.display());
        File::create(config_path).await?;
    }
    let config_file = fs::read_to_string(config_path).await?;
    let config: Config = toml::from_str(&config_file)?;
    Ok(config)
}

#[derive(Error, Debug)]
pub enum WriteconfigError {
    #[error("Failed to write config file")]
    IoError(#[from] std::io::Error),
    #[error("Failed to serialize config file")]
    TomlError(#[from] toml::ser::Error),
}

pub async fn write_to_config(config_path: &Path, config: &Config) -> Result<(), WriteconfigError> {
    fs::write(config_path, toml::to_string(config)?).await?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum GetConfigDirError {
    #[error("Failed to get config directory")]
    ProjectDirsError,
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn get_config_dir() -> Result<PathBuf, GetConfigDirError> {
    let project_dirs =
        directories::ProjectDirs::from("com", "Billy", "Billys Encrypted File Server")
            .ok_or(GetConfigDirError::ProjectDirsError)?;
    Ok(project_dirs.config_dir().to_path_buf())
}
