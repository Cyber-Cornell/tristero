"""MCP bridge: target scope and task locks are checked by the coordinator."""
import json
import os
from pathlib import Path
import ssl

import httpx
from mcp.server.fastmcp import FastMCP

from .remote import execute, rotation_command


class Coordinator:
    def __init__(self, config):
        url = config["coordinator"]
        if not url.startswith("https://") and not (config.get("insecure_local") and url.startswith("http://127.0.0.1:")):
            raise ValueError("Coordinator HTTPS required; HTTP is limited to explicit loopback development")
        verification = ssl.create_default_context(cafile=config.get("ca_file"))
        self.client = httpx.Client(base_url=url, headers={"Authorization": "Bearer " + config["token"]},
                                   verify=verification, timeout=20, trust_env=False)

    def call(self, endpoint, **body):
        response = self.client.post("/api/worker/" + endpoint, json=body)
        response.raise_for_status()
        return response.json()


class Tools:
    def __init__(self, config, task, runtime, executor=execute):
        self.coordinator = Coordinator(config)
        self.task = task
        self.runtime = Path(runtime)
        self.executor = executor

    def call(self, endpoint, **body):
        return self.coordinator.call(endpoint, task=self.task, **body)

    def target(self, id):
        context = self.coordinator.call("context")
        target = next((t for t in context["targets"] if t["id"] == id), None)
        if not target:
            raise ValueError("Target outside this worker's assignment")
        return target

    def credential(self, id, target, pending=False):
        return self.call("credential", id=id, target=target, pending=pending)

    def run(self, target_id, command, credential=None, purpose="execute", rotation=None, pending=False, timeout=120):
        target = self.target(target_id)
        auth = self.credential(credential or target["credential"], target_id, pending)
        operation = self.call("operation_start", target=target_id, command=command, purpose=purpose, rotation=rotation)["id"]
        try:
            result = self.executor(target, auth, command, self.runtime, timeout)
        except Exception as error:
            # An exception cannot prove that a remote command never started.
            self.coordinator.call("operation_finish", id=operation, result={"error": str(error)[:1000]}, uncertain=True)
            raise RuntimeError("Remote outcome uncertain; operation " + operation + " requires reconciliation") from error
        if target["transport"] == "ssh" and result["exit_code"] == 255:
            self.coordinator.call("operation_finish", id=operation, result=result, uncertain=True)
            raise RuntimeError("SSH transport lost; operation " + operation + " requires reconciliation")
        # A crash or failed result upload leaves the started operation durable.
        recorded = self.coordinator.call("operation_finish", id=operation, result=result)
        return {"operation": operation, **recorded["result"]}

    def rotate_apply(self, rotation_id):
        view = self.call("view")
        rotation = next(r for r in view["rotations"] if r["id"] == rotation_id)
        context = self.coordinator.call("context")
        credential = next(c for c in context["credentials"] if c["id"] == rotation["credential"])
        target = self.target(credential["target"])
        pending = self.credential(credential["id"], target["id"], pending=True)
        command = rotation_command(credential, pending, target)
        # Durable applying marker precedes the external mutation; no blind retry.
        self.call("rotation_step", rotation=rotation_id, action="applying", target=target["id"])
        result = self.run(target["id"], command, purpose="rotate", rotation=rotation_id)
        if result["exit_code"] != 0:
            raise RuntimeError("Rotation command failed. Verify actual account state and reconcile before retrying.")
        self.call("rotation_step", rotation=rotation_id, action="applied", target=target["id"])
        return result

    def rotate_consumer(self, rotation_id, target_id):
        rotation = next(r for r in self.call("view")["rotations"] if r["id"] == rotation_id)
        credential = next(c for c in self.coordinator.call("context")["credentials"] if c["id"] == rotation["credential"])
        template = credential["consumer_updates"].get(target_id)
        if not template:
            return {"message": "No stored credential configuration update declared; perform fresh authentication verification."}
        pending = self.credential(credential["id"], target_id, pending=True)
        target = self.target(target_id)
        import shlex
        quote = shlex.quote if target["transport"] == "ssh" else lambda s: "'" + s.replace("'", "''") + "'"
        command = template.replace("${NEW_PASSWORD}", quote(pending["password"]))
        result = self.run(target_id, command, purpose="consumer_update", rotation=rotation_id)
        if result["exit_code"] != 0:
            raise RuntimeError("Consumer configuration update failed; do not commit rotation")
        self.call("rotation_step", rotation=rotation_id, action="updated", target=target_id)
        return result

    def verify(self, rotation_id, target_id):
        rotation = next(r for r in self.call("view")["rotations"] if r["id"] == rotation_id)
        target = self.target(target_id)
        command = "id -un" if target["transport"] == "ssh" else "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"
        result = self.run(target_id, command, credential=rotation["credential"], pending=True, purpose="fresh_auth", rotation=rotation_id)
        if result["exit_code"] != 0:
            raise RuntimeError("Fresh authentication failed; do not commit rotation")
        self.call("rotation_step", rotation=rotation_id, action="verified", target=target_id)
        return result


def serve_tools():
    config = json.loads(Path(os.environ["GODSWORK_WORKER_CONFIG"]).read_text())
    tools = Tools(config, os.environ["GODSWORK_TASK"], os.environ["GODSWORK_RUNTIME"])
    server = FastMCP("godswork")

    @server.tool()
    def task_context() -> dict:
        """Read assignment, dependency graph, task discussion, and rotation journal."""
        return tools.coordinator.call("context") | tools.call("view")

    @server.tool()
    def discuss(text: str) -> dict:
        """Post a message in the task thread. Known passwords are redacted."""
        return tools.call("message", text=text)

    @server.tool()
    def remote_execute(target_id: str, command: str, timeout: int = 120) -> dict:
        """Execute on an assigned target locked by this task and record evidence. Linux: Bash; Windows: PowerShell."""
        if not command or len(command) > 20000:
            raise ValueError("Command must contain 1–20000 characters")
        return tools.run(target_id, command, timeout=timeout)

    @server.tool()
    def credential_read(credential_id: str, target_id: str, pending: bool = False) -> dict:
        """Read an explicitly scoped credential. Passwords enter model context under the team's chosen policy."""
        return tools.credential(credential_id, target_id, pending)

    @server.tool()
    def rotation_prepare(credential_id: str) -> dict:
        """Generate and durably encrypt a new password. Task must lock issuer and all consumers."""
        return tools.call("rotation_begin", credential=credential_id)

    @server.tool()
    def rotation_apply(rotation_id: str) -> dict:
        """Change the issuer's inventoried account once. Never retry an applying rotation blindly."""
        return tools.rotate_apply(rotation_id)

    @server.tool()
    def rotation_update_consumer(rotation_id: str, target_id: str) -> dict:
        """Run the team's inventoried consumer-update command with the pending password."""
        return tools.rotate_consumer(rotation_id, target_id)

    @server.tool()
    def rotation_verify(rotation_id: str, target_id: str) -> dict:
        """Verify fresh remote authentication using the new password on issuer or consumer."""
        return tools.verify(rotation_id, target_id)

    @server.tool()
    def rotation_commit(rotation_id: str, issuer_target: str) -> dict:
        """Promote the pending password only after all required updates and fresh authentications."""
        return tools.call("rotation_step", rotation=rotation_id, action="commit", target=issuer_target)

    @server.tool()
    def inject_draft(inject_id: str, response: str, evidence: list[str], checklist: str) -> dict:
        """Render the actual team template using evidence IDs from this inject task. Humans submit it."""
        return tools.call("draft", inject=inject_id, response=response, evidence=evidence, checklist=checklist)

    server.run()
