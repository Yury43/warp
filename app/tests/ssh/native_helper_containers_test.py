"""Run persistent-session tests on disposable ARM64 and x86-64 hosts without Python."""

import argparse
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

DOCKERFILE = """FROM alpine:3.22
RUN apk add --no-cache openssh \\
    && ssh-keygen -A \\
    && adduser -D tester && passwd -d tester \\
    && mkdir -m 700 /home/tester/.ssh
COPY authorized_keys /home/tester/.ssh/authorized_keys
RUN chown -R tester:tester /home/tester/.ssh && chmod 600 /home/tester/.ssh/authorized_keys
CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "PermitRootLogin=no"]
"""


@contextlib.contextmanager
def isolated_agent(key):
    with tempfile.TemporaryDirectory(prefix="wsa-", dir="/tmp") as temporary:
        path = Path(temporary) / "agent"
        process = subprocess.Popen(
            ["ssh-agent", "-D", "-a", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 10
            while not path.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("Isolated SSH agent did not start")
                time.sleep(0.05)
            environment = {**os.environ, "SSH_AUTH_SOCK": str(path)}
            subprocess.run(["ssh-add", str(key)], env=environment, check=True)
            yield environment
        finally:
            process.terminate()
            process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", help="Feature-enabled warp-oss executable")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="warp-native-ssh-") as temporary:
        directory = Path(temporary)
        key = directory / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        (directory / "authorized_keys").write_bytes(key.with_suffix(".pub").read_bytes())
        (directory / "Dockerfile").write_text(DOCKERFILE)
        for architecture in ("arm64", "amd64"):
            image = "warp-native-ssh-test:" + uuid.uuid4().hex[:12]
            container = None
            try:
                subprocess.run(
                    [
                        "docker",
                        "build",
                        "--platform",
                        "linux/" + architecture,
                        "-t",
                        image,
                        str(directory),
                    ],
                    check=True,
                )
                container = subprocess.check_output(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--platform",
                        "linux/" + architecture,
                        "-p",
                        "127.0.0.1::22",
                        image,
                    ],
                    text=True,
                ).strip()
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container,
                        "sh",
                        "-c",
                        "! command -v python && ! command -v python3",
                    ],
                    check=True,
                )
                inspected = json.loads(subprocess.check_output(["docker", "inspect", container]))
                port = inspected[0]["NetworkSettings"]["Ports"]["22/tcp"][0]["HostPort"]
                ssh = [
                    "tester@127.0.0.1",
                    "-p",
                    port,
                    "-i",
                    str(key),
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-o",
                    "UserKnownHostsFile=" + str(directory / "known_hosts"),
                ]
                deadline = time.monotonic() + 30
                while subprocess.run(
                    ["ssh", *ssh, "true"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                ).returncode:
                    if time.monotonic() > deadline:
                        raise AssertionError("SSH test host did not start")
                    time.sleep(0.2)
                command = [
                    sys.executable,
                    str(Path(__file__).with_name("persistent_sessions_test.py")),
                ]
                if args.binary:
                    command += ["--binary", os.path.abspath(args.binary)]
                subprocess.run(command + ["--", *ssh], check=True)
                agent_test = [
                    sys.executable,
                    str(Path(__file__).with_name("agent_forwarding_test.py")),
                ]
                if args.binary:
                    agent_test += ["--binary", os.path.abspath(args.binary)]
                with isolated_agent(key) as environment:
                    subprocess.run(agent_test + ["--", *ssh], env=environment, check=True)
                print(f"PASS: Linux {architecture}, no remote Python", flush=True)
            finally:
                if container:
                    subprocess.run(["docker", "rm", "-f", container], check=True)
                subprocess.run(["docker", "image", "rm", image], check=False)


if __name__ == "__main__":
    main()
