"""Exercise the built-in SSH session client against a disposable Linux SSH account."""

import argparse
import fcntl
import os
import pty
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src" / "persistent_ssh"


class Terminal:
    def __init__(self, command):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        self.process = subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=slave, start_new_session=True
        )
        os.close(slave)
        self.output = bytearray()
        self.query_tail = b""

    def send(self, data):
        os.write(self.master, data)

    def until(self, marker, timeout=30):
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            if not select.select([self.master], [], [], max(0, deadline - time.monotonic()))[0]:
                raise AssertionError("Timed out: " + repr(bytes(self.output[-2000:])))
            try:
                data = os.read(self.master, 65536)
            except OSError:
                raise AssertionError("Client exited: " + repr(bytes(self.output[-2000:])))
            if not data:
                raise AssertionError("Client closed the terminal")
            queries = self.query_tail + data
            for _ in range(queries.count(b"\x1b[6n")):
                self.send(b"\x1b[1;1R")
            self.query_tail = queries[-3:]
            self.output.extend(data)
        end = self.output.index(marker) + len(marker)
        result = bytes(self.output[:end])
        del self.output[:end]
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.wait_exit()
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        os.close(self.master)

    def wait_exit(self, timeout=30):
        deadline = time.monotonic() + timeout
        while self.process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.process.args, timeout)
            if select.select([self.master], [], [], min(remaining, 0.2))[0]:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    break
                if not data:
                    break
        self.process.wait(timeout=max(0, deadline - time.monotonic()))

    def disconnect_transport(self):
        processes = subprocess.check_output(["ps", "-axo", "pid,ppid,comm"], text=True)
        for line in processes.splitlines()[1:]:
            pid, parent, executable = line.strip().split(None, 2)
            if int(parent) == self.process.pid and os.path.basename(executable) == "ssh":
                os.kill(int(pid), signal.SIGKILL)
                return
        raise AssertionError("SSH transport was not found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary", help="Built warp-oss binary; defaults to the embedded Python client"
    )
    parser.add_argument("ssh_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    ssh_args = args.ssh_args
    if ssh_args and ssh_args[0] == "--":
        ssh_args = ssh_args[1:]
    if not ssh_args:
        parser.error("Provide a disposable SSH destination after --")
    name = "warp-test-" + uuid.uuid4().hex[:12]
    if args.binary:
        command = [args.binary, "ssh-session"]
    else:
        command = [sys.executable, str(SOURCE / "client.py")]
    command += ssh_args + ["--name", name]
    terminals = []
    try:
        first = Terminal(command)
        terminals.append(first)
        first.send(b"stty -echo; saved=kept; original_pid=$$; printf '\\nREADY-ONE\\n'\n")
        first.until(b"\r\nREADY-ONE\r\n")

        listing = subprocess.run(command + ["--list"], capture_output=True, check=True, timeout=30)
        assert name.encode() in listing.stdout, listing.stdout

        first.disconnect_transport()

        # Wait for the reconnect handshake, then use output as the readiness barrier.
        # These are probe commands, not sleeps used to infer session survival.
        deadline = time.monotonic() + 20
        while True:
            first.send(b'printf \'\\nRECONNECTED:%s:%s\\n\' "$saved" "$(( $$ == original_pid ))"\n')
            try:
                first.until(b"\r\nRECONNECTED:kept:1\r\n", timeout=2)
                break
            except AssertionError:
                if time.monotonic() > deadline:
                    raise
        print("PASS: automatic reconnect keeps the same shell PID and environment")

        program = (
            "old=$(stty -g); stty raw -echo; "
            "printf '\\033[?1049h\\033[2J\\033[H\\033[32mFULL-SCREEN\\033[0m'; "
            "key=$(dd bs=1 count=1 2>/dev/null); printf 'KEY:%s' \"$key\"; "
            "dd bs=1 count=1 >/dev/null 2>&1; stty \"$old\"; printf '\\033[?1049l'"
        )
        first.send(("sh -c " + shlex.quote(program) + "\n").encode())
        first.until(b"\x1b[32mFULL-SCREEN\x1b[0m")
        subprocess.run(command + ["--detach"], check=True, timeout=30)
        first.wait_exit()
        assert first.process.returncode == 0

        second = Terminal(command)
        terminals.append(second)
        second.until(b"\x1b[32mFULL-SCREEN\x1b[0m")
        second.send(b"x")
        second.until(b"KEY:x")
        second.send(b"q")
        second.until(b"\x1b[?1049l")
        second.send(b'printf \'\\nRESTORED:%s:%s\\n\' "$saved" "$(( $$ == original_pid ))"\n')
        second.until(b"\r\nRESTORED:kept:1\r\n")
        print("PASS: a new client restores full-screen output and attaches to the running program")

        fcntl.ioctl(second.master, termios.TIOCSWINSZ, struct.pack("HHHH", 37, 111, 0, 0))
        second.send(b"stty size; printf '\\nRESIZED\\n'\n")
        output = second.until(b"\r\nRESIZED\r\n")
        # The periodic size message may follow already-entered input; query once more after it.
        if b"37 111" not in output:
            second.send(b"stty size; printf '\\nRESIZED-AGAIN\\n'\n")
            output = second.until(b"\r\nRESIZED-AGAIN\r\n")
        assert b"37 111" in output, output
        second.send(b"exit 23\n")
        second.wait_exit()
        assert second.process.returncode == 23, second.process.returncode
        print("PASS: resize and shell exit status propagate correctly")
    finally:
        for terminal in terminals:
            terminal.close()
        subprocess.run(
            command + ["--kill"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )


if __name__ == "__main__":
    main()
