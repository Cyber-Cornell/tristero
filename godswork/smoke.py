"""A real two-instance anonymous tool-use gate, also used before enrollment."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import sys
import time

from mcp.server.fastmcp import FastMCP

from .opencode import OpenCode, ROOT, VERSION


def probe_server():
    server = FastMCP("godswork-probe")

    @server.tool()
    def probe(nonce: str) -> str:
        Path("called.txt").write_text(nonce)
        return "tool-ok:" + nonce

    server.run()


def smoke(model: str):
    run = ROOT / ".tools/data/probes" / secrets.token_hex(8)

    def check(index):
        directory = run / str(index)
        nonce = secrets.token_hex(16)
        engine = OpenCode(directory, model, [sys.executable, "-m", "godswork.smoke"],
                          {"PYTHONPATH": str(ROOT)}, local_tools=False)
        try:
            session = engine.session("Anonymous tool-use check")
            reply = engine.prompt(session, f'Call godswork_probe with nonce "{nonce}" and return its exact result. '
                                  'You must call the tool; do not simulate it.')
            if (directory / "called.txt").read_text() != nonce or "tool-ok:" + nonce not in reply:
                raise RuntimeError("Model did not complete the required tool call")
            print(f"Worker {index}: anonymous tool use passed", flush=True)
        finally:
            engine.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(check, [1, 2]))
    result = {"model": model, "version": VERSION, "checked_at": time.time()}
    receipt = ROOT / ".tools/data/anonymous-check.json"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(result))
    receipt.chmod(0o600)
    print("Anonymous concurrency gate passed. No paid fallback configured.")


if __name__ == "__main__":
    probe_server()
