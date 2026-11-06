#![expect(
    clippy::disallowed_types,
    reason = "This Unix-only client needs exec, which command::blocking::Command does not expose"
)]

#[cfg(feature = "persistent_ssh_sessions")]
use std::io::{Seek, Write};
#[cfg(feature = "persistent_ssh_sessions")]
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use warp_cli::ssh_session::SshSessionArgs;
use warp_core::features::FeatureFlag;

pub fn run(args: &SshSessionArgs) -> Result<()> {
    ensure!(
        FeatureFlag::PersistentSshSessions.is_enabled(),
        "Persistent SSH sessions are experimental. Build with --features persistent_ssh_sessions."
    );
    let mut command = Command::new("python3");
    command
        .arg("-c")
        .arg(include_str!("persistent_ssh/client.py"))
        .args(args.helper_args());
    #[cfg(feature = "persistent_ssh_sessions")]
    let helpers = bundled_helpers(&mut command)?;
    let error = command.exec();
    #[cfg(feature = "persistent_ssh_sessions")]
    drop(helpers);
    Err(error).context("Could not start the SSH session client; Python 3.9+ is required locally")
}

#[cfg(feature = "persistent_ssh_sessions")]
fn bundled_helpers(command: &mut Command) -> Result<Vec<std::fs::File>> {
    use warp_terminal::bootstrap::script_for_shell;
    use warp_terminal::shell::ShellType;

    let mut files = Vec::new();
    let mut descriptors = serde_json::Map::new();
    let init = include_str!("../assets/bundled/bootstrap/bash_init_shell.sh")
        .replace("@@WARP_SESSION_ID@@", "$WARP_SESSION_ID")
        .replace("@@USING_CON_PTY_BOOLEAN@@", "false");
    let mut bootstrap = init.into_bytes();
    bootstrap.extend_from_slice(&script_for_shell(ShellType::Bash, &crate::ASSETS));
    for (architecture, bytes) in [
        (
            "x86_64",
            include_bytes!(concat!(env!("OUT_DIR"), "/ssh-helper-x86_64")).as_slice(),
        ),
        (
            "aarch64",
            include_bytes!(concat!(env!("OUT_DIR"), "/ssh-helper-aarch64")).as_slice(),
        ),
        ("bash", bootstrap.as_slice()),
    ] {
        // Anonymous files survive exec without leaving extracted executables on the local disk.
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        file.rewind()?;
        let descriptor = file.as_raw_fd();
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) } == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        descriptors.insert(architecture.into(), descriptor.into());
        files.push(file);
    }
    command.env("WARP_SSH_HELPER_FDS", serde_json::to_string(&descriptors)?);
    Ok(files)
}
