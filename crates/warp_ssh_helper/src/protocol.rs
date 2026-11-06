use std::io::Read;
use std::path::PathBuf;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const MAX_FRAME: usize = 1024 * 1024;
pub const CHUNK: usize = 32768;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Attach,
    List,
    Status,
    Detach,
    Kill,
}

#[derive(Deserialize, Serialize)]
pub struct Request {
    pub name: String,
    pub action: Action,
    pub client: String,
    #[serde(default)]
    pub generation: Option<String>,
    #[serde(default)]
    pub offset: u64,
    pub size: [u16; 2],
    pub term: String,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub details: bool,
    #[serde(default)]
    pub existing_only: bool,
    #[serde(default)]
    pub create_only: bool,
    #[serde(default)]
    pub agent_socket: Option<PathBuf>,
    #[serde(default)]
    pub integration: Option<ShellIntegration>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ShellIntegration {
    pub session_id: u64,
    pub bootstrap: String,
}

#[derive(Deserialize, Serialize)]
pub struct SessionInfo {
    pub name: String,
    pub created_at: Option<u64>,
    pub created_at_estimated: bool,
    pub last_interaction_at: Option<u64>,
    pub state: SessionState,
    pub shell_pid: Option<u32>,
    pub output_bytes: u64,
    pub generation: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    Attached,
    Detached,
    Exited,
    Unknown,
}

pub fn frame(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 + data.len());
    bytes.push(kind);
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

pub fn json_frame(kind: u8, value: &impl Serialize) -> Vec<u8> {
    frame(
        kind,
        &serde_json::to_vec(value).expect("Protocol values are JSON serializable"),
    )
}

pub fn read_frame(reader: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    reader.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header[1..].try_into()?) as usize;
    ensure!(size <= MAX_FRAME, "Invalid session protocol frame");
    let mut data = vec![0; size];
    reader.read_exact(&mut data)?;
    Ok((header[0], data))
}

pub fn read_request(reader: &mut impl Read) -> Result<Request> {
    let (kind, data) = read_frame(reader)?;
    ensure!(kind == b'H', "Expected session handshake");
    Ok(serde_json::from_slice(&data)?)
}

#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
        self.buffer.extend_from_slice(data);
        let mut messages = Vec::new();
        let mut consumed = 0;
        while self.buffer.len() - consumed >= 5 {
            let header = &self.buffer[consumed..consumed + 5];
            let size = u32::from_be_bytes(header[1..].try_into()?) as usize;
            ensure!(size <= MAX_FRAME, "Invalid session protocol frame");
            let end = consumed + 5 + size;
            if self.buffer.len() < end {
                break;
            }
            messages.push((header[0], self.buffer[consumed + 5..end].to_vec()));
            consumed = end;
        }
        self.buffer.drain(..consumed);
        Ok(messages)
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
