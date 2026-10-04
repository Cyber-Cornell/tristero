"""Local scoreboard/inject fixture. File edits simulate changes without an LLM."""
import json
from pathlib import Path
import time

from fastapi import FastAPI
from fastapi.responses import HTMLResponse


def fixture_app(path):
    app = FastAPI(title="CCDC lab fixture portal")

    @app.get("/snapshot")
    def snapshot():
        body = json.loads(Path(path).read_text())
        return {"generated_at": time.time(), **body}

    @app.get("/", response_class=HTMLResponse)
    def page():
        return """<!doctype html><html lang=en><meta charset=utf-8><title>Lab scoreboard</title>
        <h1>Lab scoreboard and injects</h1><pre id=data></pre><script>
        async function refresh(){const r=await fetch('/snapshot');document.getElementById('data').textContent=JSON.stringify(await r.json(),null,2);}
        refresh();setInterval(refresh,5000);</script></html>"""

    return app
