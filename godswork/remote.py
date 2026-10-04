"""Native SSH and certificate-verified WinRM. Remote timeouts are uncertain."""
import os
from pathlib import Path
import subprocess
import tempfile
import json
import sys

from .opencode import ROOT


def execute(target, credential, command, runtime, timeout=120):
    if not 1 <= timeout <= 120:
        raise ValueError("Timeout must be between 1 and 120 seconds")
    username = credential.get("consumer_usernames", {}).get(target["id"], credential["username"])
    if target["transport"] == "ssh":
        known_hosts = Path(target["known_hosts"]).expanduser().resolve()
        if not known_hosts.is_file():
            raise ValueError("Verified SSH known_hosts file missing on worker")
        runtime = Path(runtime)
        runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        askpass = runtime / "askpass"
        askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$GODSWORK_SSH_PASSWORD"\n')
        askpass.chmod(0o700)
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
                       "DISPLAY": "godswork:0", "SSH_ASKPASS": str(askpass.resolve()), "SSH_ASKPASS_REQUIRE": "force",
                       "GODSWORK_SSH_PASSWORD": credential["password"]}
        argv = ["ssh", "-F", "/dev/null", "-T", "-p", str(target["port"]), "-l", username,
                "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known_hosts),
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-o", "NumberOfPasswordPrompts=1",
                "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no",
                "-o", "IdentityAgent=none", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
                target["host"], "bash -s"]
        # Bound memory use even when a target emits large output.
        with tempfile.TemporaryFile(dir=runtime) as stdout, tempfile.TemporaryFile(dir=runtime) as stderr:
            result = subprocess.run(argv, input=command.encode(), stdout=stdout, stderr=stderr,
                                    env=environment, timeout=timeout, start_new_session=True)
            stdout.seek(0); stderr.seek(0)
            out, err = stdout.read(65537), stderr.read(65537)
            return {"exit_code": result.returncode, "stdout": out[:65536].decode(errors="replace"),
                    "stderr": err[:65536].decode(errors="replace"), "truncated": len(out) > 65536 or len(err) > 65536}
    # pywinrm's operation timeout is per poll, not a total command deadline.
    # A child process gives the parent a real deadline; remote work may still need recovery.
    runtime = Path(runtime)
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment = {key:os.environ[key] for key in ("PATH", "LANG") if key in os.environ}
    environment |= {"PYTHONPATH": str(ROOT), "PYTHONPYCACHEPREFIX": str(ROOT / ".tools/cache/pycache")}
    payload = json.dumps({"target": target, "username": username, "password": credential["password"], "command": command, "timeout": timeout})
    with tempfile.TemporaryFile(dir=runtime) as stdout, tempfile.TemporaryFile(dir=runtime) as stderr:
        child = subprocess.run([sys.executable, "-m", "godswork.remote"], input=payload.encode(), env=environment,
                               stdout=stdout, stderr=stderr, timeout=timeout, start_new_session=True)
        if child.returncode:
            raise RuntimeError("WinRM subprocess failed; remote outcome uncertain")
        stdout.seek(0)
        return json.loads(stdout.read(1_000_000))


def winrm_execute(target, username, password, command, timeout):
    import winrm
    ca = Path(target["ca_file"]).expanduser().resolve()
    if not ca.is_file():
        raise ValueError("Verified WinRM CA file missing on worker")
    host = "[" + target["host"] + "]" if ":" in target["host"] else target["host"]
    session = winrm.Session(f"https://{host}:{target['port']}/wsman", auth=(username, password),
        transport="ntlm", server_cert_validation="validate", ca_trust_path=str(ca),
        read_timeout_sec=timeout + 10, operation_timeout_sec=timeout)
    result = session.run_ps("$ErrorActionPreference = 'Stop';\n" + command)
    return {"exit_code": result.status_code, "stdout": result.std_out[:65536].decode(errors="replace"),
            "stderr": result.std_err[:65536].decode(errors="replace"), "truncated": len(result.std_out) > 65536 or len(result.std_err) > 65536}


def rotation_command(credential, pending, target):
    import shlex
    account = credential["account"]
    password = pending["password"]
    kind = credential["rotation_kind"]
    if kind == "linux-local" and target["transport"] == "ssh":
        return "printf '%s:%s\\n' " + shlex.quote(account) + " " + shlex.quote(password) + " | sudo -n chpasswd"
    if target["transport"] != "winrm":
        raise ValueError("Windows/AD rotation requires WinRM")
    quote = lambda value: "'" + value.replace("'", "''") + "'"
    prefix = "$newPassword = ConvertTo-SecureString " + quote(password) + " -AsPlainText -Force;\n"
    if kind == "ad-user":
        return prefix + "Import-Module ActiveDirectory; Set-ADAccountPassword -Identity " + quote(account) + " -Reset -NewPassword $newPassword"
    if kind == "windows-local":
        return prefix + "Set-LocalUser -Name " + quote(account) + " -Password $newPassword"
    raise ValueError("Unsupported rotation kind")


if __name__ == "__main__":
    print(json.dumps(winrm_execute(**json.load(sys.stdin))))
