use std::path::PathBuf;

use thiserror::Error;

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_DATA_FAILURE: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_UNSAFE: u8 = 3;
pub const EXIT_RESOURCE: u8 = 4;

#[derive(Debug, Error)]
pub enum RarparError {
    #[error("no input paths were provided")]
    NoInput,
    #[error("input path does not exist: {0}")]
    MissingInput(PathBuf),
    #[error("invalid command line: {0}")]
    Usage(String),
    #[error("data is missing, corrupt, or insufficient: {0}")]
    Data(String),
    #[error("unsafe operation rejected: {0}")]
    Unsafe(String),
    #[error("resource limit exceeded: {0}")]
    Resource(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("RAR error: {0}")]
    Rar(#[from] unrar_rs::RarError),
    #[error("PAR2 error: {0}")]
    Par2(#[from] par2_rs::Par2Error),
    #[error("PAR3 error: {0}")]
    Par3(#[from] par3_rs::runtime::EngineError),
}

impl RarparError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoInput | Self::MissingInput(_) | Self::Usage(_) => EXIT_USAGE,
            Self::Unsafe(_) => EXIT_UNSAFE,
            Self::Resource(_) => EXIT_RESOURCE,
            Self::Io(_) | Self::Json(_) | Self::Data(_) => EXIT_DATA_FAILURE,
            Self::Rar(error) => match error {
                unrar_rs::RarError::ResourceLimit { .. } => EXIT_RESOURCE,
                unrar_rs::RarError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
                    EXIT_UNSAFE
                }
                _ => EXIT_DATA_FAILURE,
            },
            Self::Par2(error) => match error {
                par2_rs::Par2Error::ResourceLimitExceeded { .. } => EXIT_RESOURCE,
                _ => EXIT_DATA_FAILURE,
            },
            Self::Par3(error) => par3_exit_code(error),
        }
    }
}

fn par3_exit_code(error: &par3_rs::runtime::EngineError) -> u8 {
    use par3_rs::runtime::EngineError;
    match error {
        EngineError::ResourceLimit(_) => EXIT_RESOURCE,
        EngineError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists => EXIT_UNSAFE,
        EngineError::RepairInterrupted { cause, .. }
        | EngineError::OutputInterrupted { cause, .. } => par3_exit_code(cause),
        _ => EXIT_DATA_FAILURE,
    }
}
