"""Isolated native OpenCode process; no inherited provider accounts."""
import json
import os
import platform
from pathlib import Path
import secrets
import socket
import subprocess
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.18.34"


def require_ubuntu_vm():
    """Deployment guard for dedicated Ubuntu guests; not hypervisor attestation."""
    try:
        result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True,
                                text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Cannot verify worker VM. Run inside a dedicated Ubuntu VM with systemd-detect-virt installed.") from error
    hypervisor = result.stdout.strip()
    if result.returncode != 0 or hypervisor in ("", "none", "wsl") or "wsl" in platform.release().lower():
        raise ValueError("OpenCode workers require a dedicated Ubuntu VM; run this command inside the guest.")
    try:
        distribution = platform.freedesktop_os_release().get("ID")
    except OSError as error:
        raise ValueError("Cannot verify Ubuntu guest OS; check /etc/os-release inside the VM.") from error
    if distribution != "ubuntu":
        raise ValueError("OpenCode worker guest OS must be Ubuntu (os-release ID=ubuntu).")
    return hypervisor


class OpenCode:
    def __init__(self, directory: Path, model: str, mcp_command: list[str], mcp_environment=None):
        require_ubuntu_vm()
        if not model.startswith("opencode/"):
            raise ValueError("Only anonymous OpenCode models are permitted")
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.password = secrets.token_urlsafe(32)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        # An allowlist avoids inheriting unrelated provider credentials/config.
        environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR") if key in os.environ}
        environment |= {
            "HOME": str(self.directory),
            "XDG_CONFIG_HOME": str(self.directory / "config"),
            "XDG_DATA_HOME": str(self.directory / "data"),
            "XDG_STATE_HOME": str(self.directory / "state"),
            "XDG_CACHE_HOME": str(ROOT / ".tools/cache/opencode"),
            "PYTHONPYCACHEPREFIX": str(ROOT / ".tools/cache/pycache"),
            "OPENCODE_SERVER_PASSWORD": self.password,
            "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
            "OPENCODE_DISABLE_CLAUDE_CODE": "true",
            "OPENCODE_CONFIG_CONTENT": json.dumps({
                "model": model, "autoupdate": False, "share": "disabled",
                "enabled_providers": ["opencode"], "snapshot": False,
                "permission": {"*": "deny", "godswork_*": "allow"},
                "mcp": {"godswork": {"type": "local", "command": mcp_command,
                    "environment": mcp_environment or {}, "enabled": True, "timeout": 180000}},
            }),
        }
        binary = ROOT / ".tools/bin/opencode"
        if subprocess.check_output([str(binary), "--version"], text=True).strip() != VERSION:
            raise RuntimeError("OpenCode version mismatch; run scripts/setup-harness")
        self.log = open(self.directory / "server.log", "a")
        os.chmod(self.directory / "server.log", 0o600)
        self.process = subprocess.Popen([str(binary), "serve", "--port", str(self.port), "--hostname", "127.0.0.1"],
                                       cwd=self.directory, env=environment, stdout=self.log, stderr=self.log,
                                       start_new_session=True)
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}",
                                   auth=("opencode", self.password), timeout=180)
        self.model = model
        try:
            for _ in range(200):
                if self.process.poll() is not None:
                    raise RuntimeError("OpenCode exited; inspect its local server.log")
                try:
                    if self.client.get("/global/health").is_success:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("OpenCode startup timed out")
            providers = self.request("GET", "/provider")["all"]
            provider = next(p for p in providers if p["id"] == "opencode")
            catalog_model = provider["models"][model.split("/", 1)[1]]
            cost = catalog_model.get("cost", {})
            if cost.get("input") != 0 or cost.get("output") != 0:
                raise RuntimeError("Selected model is not zero cost")
        except BaseException:
            self.close()
            raise

    def request(self, method, path, **kwargs):
        response = self.client.request(method, path, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else None

    def session(self, title):
        return self.request("POST", "/session", json={"title": title})["id"]

    def prompt(self, session_id, text):
        provider, model = self.model.split("/", 1)
        data = self.request("POST", f"/session/{session_id}/message", json={
            "model": {"providerID": provider, "modelID": model},
            "parts": [{"type": "text", "text": text}],
        })
        if data.get("info", {}).get("error"):
            raise RuntimeError(json.dumps(data["info"]["error"]))
        return "\n".join(p["text"] for p in data.get("parts", []) if p.get("type") == "text")

    def abort(self, session_id):
        self.request("POST", f"/session/{session_id}/abort")

    def close(self):
        import signal
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        self.client.close()
        self.log.close()
