/// Persistent interactive SSH sessions, managed by Warp's remote PTY supervisor.
#[derive(Debug, Clone, clap::Args)]
#[command(
    about = "Keep a remote shell alive across SSH disconnects",
    long_about = "Keep a remote shell alive across SSH disconnects. Requires Python 3.9+ locally \
        and an x86-64 or ARM64 Linux host. Installs a private native helper under ~/.warp/ssh-sessions on the \
        host and records output there for replay. Use --name with an existing session name to reattach; no terminal \
        keybindings are intercepted."
)]
pub struct SshSessionArgs {
    /// SSH destination; omit to browse sessions across remembered hosts.
    pub destination: Option<String>,

    /// Name of the remote session (creation timestamp when omitted).
    #[arg(long, requires = "destination")]
    pub name: Option<String>,

    /// List sessions on the host.
    #[arg(long, group = "operation", requires = "destination")]
    pub list: bool,

    /// Choose an existing session interactively, with statistics and management actions.
    #[arg(long, group = "operation", conflicts_with = "name")]
    pub select: bool,

    /// Disconnect the attached client while leaving the shell running.
    #[arg(long, group = "operation", requires = "name")]
    pub detach: bool,

    /// Terminate the session and delete its retained output.
    #[arg(long, group = "operation", requires = "name")]
    pub kill: bool,

    /// SSH port.
    #[arg(short = 'p', long, requires = "destination")]
    pub port: Option<u16>,

    /// SSH identity file.
    #[arg(short = 'i', long, requires = "destination")]
    pub identity: Option<String>,

    /// SSH jump host.
    #[arg(short = 'J', long, requires = "destination")]
    pub jump: Option<String>,

    /// Forward the local SSH agent and restore forwarding on reconnect.
    #[arg(short = 'A', long, group = "agent_forwarding")]
    pub forward_agent: bool,

    /// Disable SSH agent forwarding, overriding SSH configuration.
    #[arg(short = 'a', long, group = "agent_forwarding")]
    pub no_forward_agent: bool,

    /// Additional OpenSSH option (repeatable).
    #[arg(short = 'o', requires = "destination")]
    pub ssh_options: Vec<String>,
}

impl SshSessionArgs {
    pub fn helper_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(destination) = &self.destination {
            args.push(destination.clone());
        }
        if let Some(name) = &self.name {
            args.extend(["--name".into(), name.clone()]);
        }
        for (enabled, flag) in [
            (self.list, "--list"),
            (self.select, "--select"),
            (self.detach, "--detach"),
            (self.kill, "--kill"),
            (self.forward_agent, "-A"),
            (self.no_forward_agent, "-a"),
        ] {
            if enabled {
                args.push(flag.into());
            }
        }
        if let Some(port) = self.port {
            args.extend(["-p".into(), port.to_string()]);
        }
        for (flag, value) in [("-i", &self.identity), ("-J", &self.jump)] {
            if let Some(value) = value {
                args.extend([flag.into(), value.clone()]);
            }
        }
        for option in &self.ssh_options {
            args.extend(["-o".into(), option.clone()]);
        }
        args
    }
}

#[cfg(test)]
#[path = "ssh_session_tests.rs"]
mod tests;
