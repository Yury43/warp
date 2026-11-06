"""Verify real forwarded-agent signing across transport loss, detach, and reattachment."""

import argparse
import hashlib
import subprocess
import sys
import time
import uuid

from persistent_sessions_test import SOURCE, Terminal


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary")
    parser.add_argument("ssh_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    ssh_args = args.ssh_args[1:] if args.ssh_args[:1] == ["--"] else args.ssh_args
    name = "warp-agent-" + uuid.uuid4().hex[:12]
    command = (
        [args.binary, "ssh-session"] if args.binary else [sys.executable, str(SOURCE / "client.py")]
    )
    command += ssh_args + ["--name", name]
    terminals = []

    def detach(terminal):
        subprocess.run(command + ["--detach", "-a"], check=True, timeout=30)
        terminal.process.wait(timeout=10)
        assert terminal.process.returncode == 0
        session_hash = hashlib.sha256(name.encode()).hexdigest()[:24]
        subprocess.run(
            [
                "ssh",
                *ssh_args,
                "-a",
                'test ! -L "$HOME/.warp/ssh-sessions/v1/' + session_hash + '/agent"',
            ],
            check=True,
            timeout=30,
        )

    try:
        first = Terminal(command + ["-A"])
        terminals.append(first)
        # Answer Alpine's initial cursor query before supplying scripted shell input.
        first.until(b"\x1b[6n")
        first.send(
            b'stty -echo; set +o emacs; set +o vi; original_pid=$$; original_agent=$SSH_AUTH_SOCK; original_target=$(readlink "$SSH_AUTH_SOCK"); printf "\\nAGENT-READY\\n"\n'
        )
        first.until(b"\r\nAGENT-READY\r\n")
        first.send(b'ssh-add -T "$HOME/.ssh/authorized_keys" && printf "\\nSIGNED-FIRST\\n"\n')
        first.until(b"\r\nSIGNED-FIRST\r\n")

        first.disconnect_transport()
        deadline = time.monotonic() + 30
        while True:
            first.send(
                b'test "$$" = "$original_pid" && test "$SSH_AUTH_SOCK" = "$original_agent" && test "$(readlink "$SSH_AUTH_SOCK")" != "$original_target" && ssh-add -T "$HOME/.ssh/authorized_keys" && printf "\\nSIGNED-RECONNECTED\\n"\n'
            )
            try:
                first.until(b"\r\nSIGNED-RECONNECTED\r\n", timeout=3)
                break
            except AssertionError:
                if time.monotonic() >= deadline:
                    raise
        print("PASS: signing works after reconnect in the same shell with the same SSH_AUTH_SOCK")
        detach(first)

        second = Terminal(command + ["-a", "-o", "ForwardAgent=yes"])
        terminals.append(second)
        second.send(
            b'test "$$" = "$original_pid" && test "$SSH_AUTH_SOCK" = "$original_agent" && test ! -L "$SSH_AUTH_SOCK" && ! ssh-add -l >/dev/null 2>&1 && printf "\\nAGENT-DISABLED\\n"\n'
        )
        second.until(b"\r\nAGENT-DISABLED\r\n")
        detach(second)
        print("PASS: detach removes the forwarding path and -a overrides ForwardAgent=yes")

        third = Terminal(command + ["-o", "ForwardAgent=yes"])
        terminals.append(third)
        third.send(
            b'test "$$" = "$original_pid" && test "$SSH_AUTH_SOCK" = "$original_agent" && ssh-add -T "$HOME/.ssh/authorized_keys" && printf "\\nSIGNED-REATTACHED\\n"\n'
        )
        third.until(b"\r\nSIGNED-REATTACHED\r\n")
        third.send(b"exit\n")
        third.process.wait(timeout=10)
        assert third.process.returncode == 0
        print("PASS: a fresh attachment restores signing through ForwardAgent=yes")
    finally:
        for terminal in terminals:
            terminal.close()
        subprocess.run(
            command + ["--kill", "-a"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )


if __name__ == "__main__":
    main()
