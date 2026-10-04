import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from cryptography.fernet import Fernet, InvalidToken
import uvicorn

from .opencode import ROOT
from .store import Store


def key_prompt():
    return getpass.getpass("Vault key (from initialization; never sent to models): ").encode()


def private_file(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as handle:
        handle.write(text)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Godswork lab harness")
    parser.add_argument("--db", type=Path, default=ROOT / ".tools/data/coordinator.sqlite")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("init"); p.add_argument("username")
    p = commands.add_parser("user"); p.add_argument("username")
    p = commands.add_parser("enroll"); p.add_argument("id"); p.add_argument("--url", required=True); p.add_argument("--ca", type=Path); p.add_argument("--out", type=Path, required=True); p.add_argument("--insecure-local", action="store_true"); p.add_argument("--coordinator", action="store_true")
    p = commands.add_parser("inventory"); p.add_argument("path", type=Path)
    p = commands.add_parser("credential"); p.add_argument("id"); p.add_argument("path", type=Path)
    p = commands.add_parser("serve"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8443); p.add_argument("--cert", type=Path); p.add_argument("--key", type=Path); p.add_argument("--portal"); p.add_argument("--template", type=Path); p.add_argument("--insecure-local", action="store_true")
    p = commands.add_parser("fixture"); p.add_argument("--path", type=Path, default=ROOT / "examples/portal.json"); p.add_argument("--port", type=int, default=8088)
    p = commands.add_parser("smoke"); p.add_argument("--model", default="opencode/space-bunny-free")
    p = commands.add_parser("worker"); p.add_argument("config", type=Path); p.add_argument("--model", default="opencode/space-bunny-free")
    p = commands.add_parser("coordinator"); p.add_argument("config", type=Path); p.add_argument("--model", default="opencode/space-bunny-free")
    p = commands.add_parser("preflight"); p.add_argument("config", type=Path)
    commands.add_parser("tools")
    commands.add_parser("coordinator-tools")
    p = commands.add_parser("backup"); p.add_argument("path", type=Path)
    p = commands.add_parser("export-vault"); p.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "serve":
        from .opencode import require_ubuntu_vm
        require_ubuntu_vm()
    if args.command == "smoke":
        from .smoke import smoke
        smoke(args.model); return
    if args.command == "worker":
        from .worker import run_worker
        run_worker(args.config, args.model); return
    if args.command == "coordinator":
        from .coordinator import run_coordinator
        run_coordinator(args.config, args.model); return
    if args.command == "coordinator-tools":
        from .coordinator import serve_tools
        serve_tools(); return
    if args.command == "preflight":
        from .worker import preflight
        preflight(args.config); return
    if args.command == "tools":
        from .tools import serve_tools
        serve_tools(); return
    if args.command == "fixture":
        from .fixture import fixture_app
        uvicorn.run(fixture_app(args.path), host="127.0.0.1", port=args.port, access_log=False); return
    if args.command == "init":
        from .store import identifier
        identifier(args.username)
        if args.db.exists():
            raise ValueError("Database already exists")
        password = getpass.getpass("New dashboard password (12+ characters): ")
        if password != getpass.getpass("Repeat dashboard password: "):
            raise ValueError("Passwords differ")
        if len(password) < 12:
            raise ValueError("Dashboard passwords must have at least 12 characters")
        key = Fernet.generate_key()
        Store(args.db, key).initialize(args.username, password)
        print("Save this vault key offline. It will NOT be saved on disk:\n" + key.decode())
        return
    if not args.db.is_file():
        raise ValueError("Coordinator database missing; initialize it with the init command")
    store = Store(args.db, key_prompt())
    # Prove the supplied key can unlock existing credentials before proceeding.
    with store.transaction() as db:
        for credential in store.all(db, "credential"):
            store.vault.decrypt(credential["sealed"].encode())
    if args.command == "user":
        store.initialize(args.username, getpass.getpass("New dashboard password: "))
    elif args.command == "enroll":
        if args.out.exists():
            raise ValueError("Enrollment output already exists")
        from .tools import Coordinator
        config = {"id": args.id, "coordinator": args.url, "ca_file": str(args.ca.resolve()) if args.ca else None,
                  "insecure_local": args.insecure_local, "token": "validation", "role": "coordinator" if args.coordinator else "worker"}
        Coordinator(config).client.close()
        config["token"] = store.enroll(args.id, role=config["role"])
        private_file(args.out, json.dumps(config, indent=2))
        print("Agent token saved to " + str(args.out) + "; copy securely, chmod 600, and adjust guest-local CA path.")
    elif args.command == "inventory":
        store.inventory(json.loads(args.path.read_text()))
    elif args.command == "credential":
        store.add_credential(args.id, json.loads(args.path.read_text()), getpass.getpass("Current account password: "))
    elif args.command == "backup":
        store.backup(args.path)
        print("Encrypted database backed up; retain the separate vault key.")
    elif args.command == "export-vault":
        private_file(args.path, json.dumps(store.export_vault(), indent=2))
        print("Plaintext recovery export saved with mode 600. Store it offline and remove the local copy when finished.")
    elif args.command == "serve":
        if not (args.cert and args.key) and not (args.insecure_local and args.host == "127.0.0.1"):
            raise ValueError("TLS certificate/key required except explicit loopback development")
        if args.insecure_local and args.host != "127.0.0.1":
            raise ValueError("Insecure mode is restricted to loopback")
        if args.template:
            from string import Template
            template = Template(args.template.read_text())
            if not template.is_valid() or not set(template.get_identifiers()).issubset({"title", "instructions", "response", "evidence", "checklist", "deadline"}):
                raise ValueError("Template must use only documented $placeholders; escape literal dollars as $$")
        from .app import create_app
        uvicorn.run(create_app(store, args.portal, args.template, args.insecure_local), host=args.host, port=args.port,
                    ssl_certfile=str(args.cert) if args.cert else None, ssl_keyfile=str(args.key) if args.key else None,
                    access_log=False, proxy_headers=False)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(str(error))
    except InvalidToken:
        sys.exit("Incorrect vault key or damaged encrypted credential")
