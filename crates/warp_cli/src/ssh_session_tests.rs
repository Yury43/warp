use clap::Parser;

use crate::{Args, Command};

#[test]
fn persistent_ssh_without_a_host_opens_the_combined_picker() {
    let args = Args::try_parse_from(["warp-oss", "ssh-session"]).unwrap();
    let Some(Command::SshSession(args)) = args.command() else {
        panic!("expected SSH session command");
    };
    assert!(args.destination.is_none());
    assert!(args.helper_args().is_empty());
}

#[test]
fn persistent_ssh_named_sessions_require_a_host() {
    assert!(Args::try_parse_from(["warp-oss", "ssh-session", "--name", "work"]).is_err());
    assert!(Args::try_parse_from(["warp-oss", "ssh-session", "--list"]).is_err());
    assert!(Args::try_parse_from(["warp-oss", "ssh-session", "-p", "2222"]).is_err());
}

#[test]
fn persistent_ssh_preserves_quoted_ssh_option_values() {
    let args = Args::try_parse_from([
        "warp-oss",
        "ssh-session",
        "user@host",
        "--name",
        "build",
        "-o",
        "ProxyCommand=ssh jump -W %h:%p",
        "-i",
        "/path with spaces/key",
        "-p",
        "2222",
    ])
    .unwrap();
    let Some(Command::SshSession(args)) = args.command() else {
        panic!("expected SSH session command");
    };
    assert_eq!(
        args.helper_args(),
        [
            "user@host",
            "--name",
            "build",
            "-p",
            "2222",
            "-i",
            "/path with spaces/key",
            "-o",
            "ProxyCommand=ssh jump -W %h:%p",
        ]
    );
}

#[test]
fn persistent_ssh_rejects_conflicting_management_actions() {
    assert!(
        Args::try_parse_from([
            "warp-oss",
            "ssh-session",
            "host",
            "--name",
            "work",
            "--detach",
            "--kill"
        ])
        .is_err()
    );
}

#[test]
fn persistent_ssh_passes_agent_forwarding_to_the_transport() {
    let args = Args::try_parse_from(["warp-oss", "ssh-session", "-A", "host"]).unwrap();
    let Some(Command::SshSession(args)) = args.command() else {
        panic!("expected SSH session command");
    };
    assert_eq!(args.helper_args(), ["host", "-A"]);
}

#[test]
fn persistent_ssh_passes_explicitly_disabled_agent_forwarding() {
    let args = Args::try_parse_from(["warp-oss", "ssh-session", "-a", "host"]).unwrap();
    let Some(Command::SshSession(args)) = args.command() else {
        panic!("expected SSH session command");
    };
    assert_eq!(args.helper_args(), ["host", "-a"]);
}

#[test]
fn persistent_ssh_rejects_conflicting_agent_forwarding_flags() {
    assert!(Args::try_parse_from(["warp-oss", "ssh-session", "-A", "-a", "host"]).is_err());
}

#[test]
fn persistent_ssh_lists_sessions_without_a_name() {
    let args = Args::try_parse_from(["warp-oss", "ssh-session", "host", "--list"]).unwrap();
    let Some(Command::SshSession(args)) = args.command() else {
        panic!("expected SSH session command");
    };
    assert_eq!(args.helper_args(), ["host", "--list"]);
}

#[test]
fn persistent_ssh_selects_sessions_without_creating_a_name() {
    let args = Args::try_parse_from(["warp-oss", "ssh-session", "host", "--select", "-A"]).unwrap();
    let Some(Command::SshSession(args)) = args.command() else {
        panic!("expected SSH session command");
    };
    assert_eq!(args.helper_args(), ["host", "--select", "-A"]);
}

#[test]
fn persistent_ssh_picker_rejects_a_name_or_another_operation() {
    assert!(
        Args::try_parse_from([
            "warp-oss",
            "ssh-session",
            "host",
            "--select",
            "--name",
            "work"
        ])
        .is_err()
    );
    assert!(
        Args::try_parse_from(["warp-oss", "ssh-session", "host", "--select", "--list"]).is_err()
    );
}

#[test]
fn persistent_ssh_requires_a_name_to_detach() {
    let error = Args::try_parse_from(["warp-oss", "ssh-session", "host", "--detach"]).unwrap_err();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn persistent_ssh_requires_a_name_to_kill() {
    let error = Args::try_parse_from(["warp-oss", "ssh-session", "host", "--kill"]).unwrap_err();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}
