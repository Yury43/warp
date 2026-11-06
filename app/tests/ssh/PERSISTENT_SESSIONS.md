# Persistent SSH sessions (experimental)

Build the native helpers, then the GUI binary with the opt-in feature. Building the helpers requires
`cargo-zigbuild`, Zig, and the two Rust musl targets (`rustup target add x86_64-unknown-linux-musl
aarch64-unknown-linux-musl`). These are development dependencies only:

```sh
./script/build-ssh-helpers
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  cargo build --locked --bin warp-oss --features persistent_ssh_sessions
```

On Linux clients, omit `DEVELOPER_DIR`. Run the command in a terminal pane:

```sh
./target/debug/warp-oss ssh-session user@host --name work
```

The local client requires Python 3.9 or newer. The Linux host does **not** need Python, a compiler,
or extra shared libraries: Warp includes static Rust helpers for x86-64 and ARM64. Setup uses SSH,
`sh`, `uname`, `stat`, `sha256sum`, `mktemp`, and standard file utilities (GNU or BusyBox). The account
must be able to run executables from its home directory; root access is not required.

SSH config aliases, `-p`, `-i`, `-J`, and repeatable `-o` options are supported.
Authentication and host-key verification use OpenSSH.
Automatic reconnect uses noninteractive authentication; use an SSH key or an SSH agent for it.

Use `-A` to forward your local SSH agent:

```sh
./target/debug/warp-oss ssh-session -A user@host --name work
```

`ForwardAgent` in SSH configuration or `-o ForwardAgent=yes` also works. `-a` explicitly disables
forwarding. The remote shell receives a stable `SSH_AUTH_SOCK` path that points to the current
connection's forwarded agent. Reconnect or reattach updates that path, including for processes
already running in the session. Detach removes the path; while disconnected, agent requests can
fail and must be retried after reconnecting. OpenSSH handles the agent protocol and retains keys
locally. Agent forwarding requires an available local agent and permission from the SSH server.

Sessions created before this support was added need a new session name to use forwarding. Attaching
with a forwarded agent to an older supervisor reports this explicitly and leaves that session alive.

Without `--name`, each invocation creates a new session named `YYYY.MM.DD-HH:MM:SS` in the client's
local time and prints its name. If that timestamp already exists, retry in the next second.
Automatic reconnect keeps that same name. Use `--name <printed-name>` to reattach later, or `--list`
to find it. An explicit name creates a named shell or attaches to the existing one.

Transport loss reconnects automatically. Closing the client or Warp leaves the remote shell and its
programs running. After restarting Warp, run the command with the same explicit name to reattach.
From a second local pane:

```sh
./target/debug/warp-oss ssh-session
./target/debug/warp-oss ssh-session -A user@host --select
./target/debug/warp-oss ssh-session user@host --list
./target/debug/warp-oss ssh-session user@host --name work --detach
./target/debug/warp-oss ssh-session user@host --name work --kill
```

Without a destination, `ssh-session` opens the combined picker across remembered hosts. Successful
connections and explicit `--list` queries remember the host and its SSH connection options in the
private local file `~/.warp/ssh-session-hosts.json`. To add a host without creating a session, run
`ssh-session user@host --list`. The combined picker queries up to four hosts concurrently and shows
the host beside each session. Unavailable hosts are reported without blocking other results or
Escape. Sessions with identical names on different hosts remain separate. SSH config aliases work;
the picker does not scan networks or import every host from SSH configuration.

Saved connection options include ports, identity-file paths, jump hosts, additional `-o` options,
and agent-forwarding preferences. `ssh-session -A` or `ssh-session -a` overrides forwarding for the
combined picker. Attaching refreshes the selected host's helper and shell integration as needed.
Set `WARP_SSH_HOSTS_FILE` to use a different host registry.

`--select` opens an interactive picker. Use Up/Down arrows to highlight a session and Enter to
take it over, or type its number and press Enter. Long lists scroll to keep the selection visible.
Each session occupies one row showing its number, name, host in the combined picker, and
attached/detached/exited status. Actions apply directly to the highlighted session: `A` attaches, `D` detaches, and `K` kills. Enter takes over by disconnecting any
current client and attaching this pane. Escape exits; `Q` also works. Killing requires typing `kill`
to confirm and terminates its processes and deletes retained output. Selecting a session that
has disappeared never creates a replacement shell. `--list` remains a plain list of names.
Single-key shortcuts accept either case and act immediately without Enter. Typing a session number
or the confirmation word `kill` still uses Enter.

The first row, `0. NEW`, opens the known-host list when selected with Enter. Choose a host with Up/Down
and Enter (or its number and Enter); Warp creates and attaches a new shell using that host's saved
connection options and the creation timestamp as its name. Escape returns to the session list without
creating anything. `NEW` remains available when no existing sessions are listed. Sessions are numbered
from 1; the session count excludes `NEW`.

The list refreshes automatically every five seconds after the preceding query completes.
Updates preserve the highlighted session by identity; if it disappears, select another session before
acting. Refreshes run in the background, so network loss does not prevent Escape from closing the
picker. Sessions started by older supervisors remain selectable, with unavailable state shown as
unknown. `--select` requires an interactive
terminal and cannot be combined with `--name` or another management operation.

`--detach` and `--kill` require an explicit `--name`. `--detach` disconnects the current client, including one waiting to reconnect. `--kill` terminates
the session and deletes its retained output. Ordinary `exit` ends the shell and returns its exit
status. A second client cannot silently take over an attached session. Session names identify shells
within the remote Unix account; different SSH aliases reaching that account see the same sessions.

## Behavior and limits

This is a byte-stream terminal connection: no tmux, status bar, key prefix, or substituted `TERM`.
Ctrl-C, bracketed paste, terminal colors, mouse sequences, and application input pass through during
live operation. Terminal resizing is forwarded to the remote PTY. Input already accepted by the
supervisor is deduplicated on reconnect. Keystrokes entered while disconnected are discarded rather
than unexpectedly executed later; input waits for output restoration on a fresh attachment.

A private native helper is installed under `~/.warp/ssh-sessions/v1` on the remote host after its
SHA-256 checksum is verified. The matching Linux binary is embedded in Warp, so moving the Warp
executable does not require copying helper files alongside it. A detached
supervisor owns each PTY independently of the SSH process. Output is retained in an owner-only file
for the lifetime of the session; memory usage is bounded, but disk usage grows with output. End
sessions you no longer need. If a shell exits while detached, its final output is kept until the next
attachment consumes it or `--kill` removes it. Helper files and empty lock directories may remain.

Transport reconnect resumes from the last delivered byte without replaying old output. A new client
replays retained terminal output, suppressing historical device queries, clipboard operations, and
shell hooks, then requests a redraw at the current size. This restores ordinary text and ANSI
full-screen output, but is not a serialized terminal-state snapshot: historical resize reflow and
graphics protocols may not reproduce exactly. An application waiting for a terminal-query response
at detachment may require a redraw or restart. Live terminal protocol bytes are not filtered.

New Bash sessions launched from a new pane in this build use Warp's shell bootstrap, Blocks,
editor, and completion menu. Completion generators run over the persistent PTY rather than an SSH
ControlMaster, so reconnecting restores the same generator functions and shell environment.
Reattachment restores the latest shell metadata and running-command hook without sourcing startup
files again or sending bootstrap commands into a foreground program. Historical output is replayed
as terminal output; historical commands are not reconstructed as separate Warp Blocks.

Existing sessions retain their original supervisor and shell setup. A session created before shell
integration remains usable with native Bash input; create a new named session to enable integration.
Other remote shells and clients outside Warp continue to use native shell input. Integrated sessions
must be reattached from the updated Warp app. Automatic reopening of SSH tabs, remote agent services,
X11 forwarding, and multiple simultaneous viewers are not integrated. Ordinary `ssh` behavior is
unchanged.
Remote reboots, a killed supervisor, disk exhaustion, and host policies that kill user processes on
logout remain outside session-survival guarantees. Automatic reconnect refuses to replace a lost
session with a new shell.

Existing sessions started by the previous Python supervisor remain attachable through the same
protocol. They keep their original supervisor until they end; newly created sessions use Rust.

`script/build-ssh-helpers` writes to `target/persistent-ssh-helpers` and checks the ELF architecture
and absence of a dynamic loader or shared-library requirements. Set `WARP_SSH_HELPER_DIR` for a
custom asset directory when building helpers and Warp. Rebuild the helpers after changing
`crates/warp_ssh_helper`; ordinary builds with the feature disabled do not require these assets.

## Verification

The protocol and PTY tests spawn real shells in private temporary directories:

```sh
cargo build -p warp_ssh_helper
cargo nextest run -p warp_ssh_helper
python3 app/src/persistent_ssh/session_tests.py -v
cargo nextest run -p warp_cli -E 'test(persistent_ssh)'
```

Run the end-to-end test against a disposable Linux SSH account. It creates a unique session,
interrupts the SSH transport, reattaches a full-screen program from a fresh client, and cleans up:

```sh
python3 app/tests/ssh/persistent_sessions_test.py \
  --binary ./target/debug/warp-oss -- testuser@linux-host -i /path/to/test-key
```

Omit `--binary` and set `WARP_SSH_HELPER_DIR=$PWD/target/persistent-ssh-helpers` to exercise the local
Python client directly. The end-to-end test does not invoke Python remotely.

With Docker and support for running ARM64 and x86-64 containers, test both architectures on
disposable Alpine SSH hosts that explicitly have no Python installed:

```sh
python3 app/tests/ssh/native_helper_containers_test.py --binary ./target/debug/warp-oss
```

The test binds SSH only to localhost and removes its containers and images afterward. For the PTY
suite on a Linux development host, set `WARP_SSH_HELPER_BINARY` to the matching native helper;
Python is needed there only to run the test harness.

The container tests also start an isolated local `ssh-agent`, load only a disposable test key, and
verify remote signatures before and after transport loss, explicit detach, `-a`, and reattachment
with `ForwardAgent=yes`. They do not use the developer's personal agent or keys.
