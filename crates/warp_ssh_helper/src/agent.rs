use std::os::unix::fs::{FileTypeExt, MetadataExt, symlink};
use std::path::Path;
use std::{fs, io};

use anyhow::{Result, ensure};

pub fn clear(directory: &Path) -> Result<()> {
    match fs::remove_file(directory.join("agent")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn update(directory: &Path, target: Option<&Path>) -> Result<()> {
    let Some(target) = target else {
        return clear(directory);
    };
    let info = fs::symlink_metadata(target)?;
    ensure!(
        target.is_absolute()
            && info.file_type().is_socket()
            && info.uid() == unsafe { libc::getuid() },
        "Invalid forwarded SSH agent socket"
    );
    let temporary = directory.join("agent.next");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Existing shells retain this pathname while sshd creates a new socket on each connection.
    symlink(target, &temporary)?;
    fs::rename(temporary, directory.join("agent"))?;
    Ok(())
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
