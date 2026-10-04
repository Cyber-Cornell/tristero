# Godswork competition lab harness

A coordinator on one competitor's Linux/WSL2 laptop dispatches autonomous OpenCode workers running inside dedicated Ubuntu VMs to assigned remote hosts. Each competitor hosts a worker VM on their laptop; the worker VM is separate from the Windows AD and Ubuntu machines being defended. SQLite stores tasks, host locks, service dependencies, discussion, evidence, and an encrypted credential vault. Competitors review inject drafts and submit them themselves.

The initial pilot covers Ubuntu/Nginx/SSSD and Windows AD. Router skills and real competition portal adapters are deferred. No external inject submission or paid-model fallback is implemented.

## Install and verify anonymous access

Workers require a dedicated Ubuntu VM with Python 3.11+, OpenSSH, `systemd-detect-virt`, and internet access. Linux, Windows, and macOS laptops can host the Ubuntu guest through their hypervisor. Run all worker installation, anonymous smoke checks, preflight, and worker commands **inside the guest**. The coordinator can run on the competitor's Linux/WSL2 host because it does not run OpenCode. Installation and runtime state stay under `.tools/`; nothing changes global agent configuration.

Create one Ubuntu worker guest per competitor using the team's existing hypervisor. Clone a clean guest before enrollment, then give each clone its own hostname, enrollment token, and `.tools/` state. Take a clean snapshot before importing credentials. Disable shared host folders, clipboard, drag-and-drop, and device passthrough. Keep the repo, remote-execution tools, model transcripts, and worker credentials in the guest. Configure networking for the coordinator, assigned lab targets, and approved anonymous AI endpoints; verify the required routes from inside the VM. VM provisioning and hypervisor networking remain team-managed.

Worker startup, preflight, and every native OpenCode launch require both `systemd-detect-virt --vm` to identify a VM and `os-release` to report `ID=ubuntu`. Other guest distributions, bare-metal hosts, WSL, and environments without working detection are rejected, with no host-mode override. Containers alone do not meet this requirement. Detection is a deployment guard, not an attestation of hypervisor isolation or network policy.

```bash
python3 scripts/setup-harness
./scripts/godswork smoke
```

The installer pins OpenCode **1.18.34**, verifies its release archive digest, and installs the locked Python dependencies in `.tools/harness-venv`. The smoke command starts two isolated native OpenCode servers and requires actual concurrent anonymous MCP calls. Successful checks produce a receipt valid for 24 hours on that machine.

`opencode/space-bunny-free` passed the live concurrency/tool-use check during implementation. `big-pickle` and `ling-3.0-flash-fin-free` were rejected by the provider in this environment. Availability can change: workers back off rather than switching to paid providers. To select a different anonymous zero-cost model, run `smoke --model opencode/NAME` and use the same `--model` for the worker. The worker's native catalog must report zero input/output cost.

## Supplied lab prerequisites

- One Windows Server AD VM with a licensed installation, domain DNS, a verified HTTPS WinRM listener on 5986, and an inventoried administrative account authorized for remoting.
- One Ubuntu VM joined to that domain through SSSD, serving the required Nginx endpoint. Enable password SSH login for the pilot's inventoried management and domain accounts. Give the Linux management account the required `sudo -n` privileges; retain a separate recovery path.
- Verify AD user resolution and SSH login manually before the exercise. For the example's rotated AD administrator, the domain username must also be allowed to SSH into Linux. A generic nonprivileged AD account may not be allowed to use WinRM; the pilot's fresh-authentication check requires an account that can.
- Supply verified SSH host keys and the WinRM CA certificate on the appropriate worker. Paths in the inventory are **worker-local**, resolved relative to this checkout. Host key checks and TLS certificate verification are mandatory.
- Set up the VMs and domain separately. This harness does not provision machines, domain joins, or the initial trust material.

## Coordinator setup

Initialize an individual dashboard account. Save the generated vault key offline: it is printed once and is not saved to disk. Every administrative CLI invocation and coordinator startup prompts for that key.

```bash
./scripts/godswork init captain
./scripts/godswork user teammate
```

Use a team-issued TLS certificate valid for the coordinator's LAN hostname. Copy its CA certificate to competitors' machines. For a self-contained practice CA, the following creates files only in `.tools/` (replace the hostname/IP before use):

```bash
mkdir -p .tools/config/tls
chmod 700 .tools/config/tls
openssl req -x509 -newkey rsa:3072 -nodes -days 7 \
  -keyout .tools/config/tls/key.pem -out .tools/config/tls/cert.pem \
  -subj '/CN=coordinator.lab.test' \
  -addext 'subjectAltName=DNS:coordinator.lab.test,IP:192.168.56.1'
chmod 600 .tools/config/tls/key.pem
```

Enroll the two workers and securely transfer each configuration into its competitor's worker VM. Adjust each file's CA path to the certificate's location inside that guest; protect the files with mode 600. Enrollment tokens are separate and revocable.

```bash
./scripts/godswork enroll linux-student \
  --url https://coordinator.lab.test:8443 --ca .tools/config/tls/cert.pem \
  --out .tools/config/linux-worker.json
./scripts/godswork enroll ad-student \
  --url https://coordinator.lab.test:8443 --ca .tools/config/tls/cert.pem \
  --out .tools/config/ad-worker.json
```

Copy the example inventory to `.tools/config/inventory.json`, edit hosts, ports, worker IDs, and worker-local trust-file paths, then import it. Enroll all named workers before import. Inventory edits are rejected while target locks exist. Dependencies must reference known services and be acyclic.

```bash
cp examples/inventory.json .tools/config/inventory.json
./scripts/godswork inventory .tools/config/inventory.json
./scripts/godswork credential linux-admin examples/linux-admin.json
./scripts/godswork credential ad-admin examples/ad-admin.json
```

Credential import prompts for passwords rather than putting them in shell history. Modify the credential JSON if account names differ. Only `rotate: true` accounts can use rotation tools. Declare every consumer before rotating a shared credential. SSH supports password/keyboard-interactive authentication; the pilot does not implement private-key credential storage.

Start the fixture portal in one terminal, then the coordinator in another:

```bash
cp examples/portal.json .tools/config/portal.json
./scripts/godswork fixture --path .tools/config/portal.json
./scripts/godswork serve --host 0.0.0.0 \
  --cert .tools/config/tls/cert.pem --key .tools/config/tls/key.pem \
  --portal http://127.0.0.1:8088/snapshot
```

Open `https://coordinator.lab.test:8443` and sign in. Keep this laptop awake. Workers make outbound coordinator connections; their OpenCode servers bind to localhost and require random HTTP authentication.

Inside **each dedicated Ubuntu worker VM's own checkout**, install, run the anonymous smoke check, securely copy its configuration, then start it:

```bash
chmod 600 .tools/config/linux-worker.json
./scripts/godswork preflight .tools/config/linux-worker.json
./scripts/godswork worker .tools/config/linux-worker.json
# Inside the AD competitor's worker VM, use ad-worker.json instead.
```

Explicit loopback-only development without TLS is available with `serve --insecure-local` and enrollment `--url http://127.0.0.1:8443 --insecure-local` when coordinator and worker run inside the same VM. It cannot be exposed on a LAN or used across the guest/host boundary: a worker VM's loopback address is its own guest. Use the coordinator's reachable HTTPS hostname for separate worker VMs. The fixture portal always binds to the coordinator's loopback interface.

## Tasks, dependencies, and opening playbook

Create tasks in the dashboard, naming target IDs and precise desired outcomes. A task involving both `ad` and `linux` is shared by their owners and locks both targets. Each worker executes only on its own assigned targets. Participants coordinate through the task thread and a readiness barrier; the locks release when everyone completes with recorded remote evidence.

For an opening exercise, use targets `ad,linux` and instructions such as:

> Inventory the two assigned hosts and their scored services, verify access and recoverable configuration, rotate the inventoried linux-admin and ad-admin credentials through the journal, preserve AD-backed Linux SSH login and Nginx, then apply justified hardening. Coordinate rotation IDs in this thread. Verify fresh authentication on the issuer and every consumer before committing, and verify scored service behavior after changes.

The worker loads the opening skill plus Linux or Windows/AD skills according to its assignments. Modify the Markdown under `skills/` to refine the team's playbooks. The harness sends those instructions with the native OpenCode session; no additional swarm framework is needed.

The fixture portal refreshes timestamps on each `/snapshot` request. Edit `.tools/config/portal.json` to make a service `down`; the coordinator polls every 30 seconds and creates a deduplicated outage task with the service's dependency targets. Missing observations are unknown/stale, not inferred failures. Stop the portal to exercise stale-source behavior.

## Credential rotation and recovery

The issuer generates and encrypts a pending password **before** mutation. `applying` is recorded before running the account reset. Issuer and consumer workers verify fresh authentication, then the issuer promotes the password to active. The example's SSSD login does not require a stored-password update; it needs a fresh AD-backed Linux login.

For services that store a password, define `consumer_updates` in the credential JSON, keyed by consumer target. Its trusted Bash/PowerShell template can use `${NEW_PASSWORD}`; the worker replaces that token with a shell-quoted password. The template must use the replacement as a complete argument, not inside additional quotes. It runs with the consumer target's management credential and must exit nonzero on failure. Record a successful update before committing. This pilot's automatic consumer check verifies remote login, not every application's protocol; application-specific functional checks must also be included in the task.

Remote exceptions, expired leases, stop/revoke, and pauses retain host locks and require reconciliation. They do not prove a remote command stopped. Pending or applying rotations cannot be blindly replayed. Global resume permits new work but does not resume an uncertain task.

1. Stop affected workers and confirm remote commands have ended using the recovery access path.
2. Obtain the previous and pending passwords with the offline CLI export below, and manually verify which credentials actually work on issuer and every consumer.
3. Complete the interrupted rotation everywhere, or restore the previous password everywhere.
4. Record the matching pending/previous recovery and a verification note in the dashboard rotation journal.
5. Reconcile the uncertain task with a remote-quiescence note, release its locks, and create a new task if further work is needed.

```bash
./scripts/godswork backup .tools/data/backups/round-1.sqlite
./scripts/godswork export-vault .tools/data/recovery.json
```

Backups contain the encrypted vault, users, worker-token hashes, and coordination state; keep the separate vault key offline. Recovery exports are plaintext, mode 600, and include pending passwords. Secure them offline and remove local copies afterward. A full recovery uses the same database and vault key; replace the default DB while the coordinator is stopped, or start with `./scripts/godswork --db PATH serve ...`. Workers reconnect, and expired active tasks retain their locks.

Passwords are allowed in model context under the chosen team policy. Shared threads and ordinary coordinator logs redact known active, historical, and pending passwords. OpenCode stores model transcripts locally; those may contain passwords and follow the selected provider's data-use policy. Protect worker state and enrollment files. The vault key itself is never sent to workers or models. Assignment enforcement protects tool calls; remote administrative access is not a network sandbox and cannot prevent an administrator from reaching other hosts through an assigned system.

## Actual team inject template

Inject rendering is disabled until the team's template is supplied. The pilot renderer accepts a UTF-8 text/Markdown template using Python `string.Template` placeholders:

`$title`, `$instructions`, `$response`, `$evidence`, `$checklist`, `$deadline`

Escape literal dollar signs as `$$`. Preserve the team's required headings and fields when adapting its template. Word/PDF output is not implemented. Restart the coordinator with `--template .tools/config/team-inject.md` after supplying it.

Assign an imported inject to its evidence targets in the dashboard. Workers collect operation evidence and render a draft. Review the response, checks, and actual evidence, download it, and submit through the competition portal yourself. “Mark manually submitted” records the human action; it never contacts a submission endpoint.

## Checks and interfaces

```bash
PYTHONPYCACHEPREFIX="$PWD/.tools/cache/pycache" .tools/harness-venv/bin/python -m unittest discover -s tests -v
./scripts/godswork smoke
```

Tests exercise concurrent claims, scope enforcement, credential access, restart/expiry, failed commands, uncertain rotation, consumer verification, authentication/CSRF, scoreboard deduplication, template prerequisites, encrypted backup, and the worker's coordination barrier. Remote executors are simulated; use the supplied VMs for live acceptance.

Preflight checks Ubuntu guest OS and worker VM detection, coordinator authentication, assignments, management credential presence, local trust files, endpoint reachability, and the WinRM server certificate. It does not claim the SSH host key matches until the first strictly verified SSH connection, or that account login works until a task records it.

The coordinator publishes OpenAPI documentation at `/docs`. Worker operations use authenticated `POST /api/worker/{action}` calls: heartbeat, context, claim, view, message, credential, operation_start/finish, ready/complete, rotation_begin/step, and draft. Human endpoints provide login, state, tasks, control, credentials, recovery, and inject review. HTTP errors do not authorize retries of remote mutations.

The portal adapter expects a JSON `/snapshot` response with `generated_at` (Unix seconds), services (`id`, `status`: up/down/unknown), and injects (`id`, `title`, `instructions`, `deadline`). A real event adapter must normalize its authenticated API/pages into that shape and retain source timestamps. No real event login or scraper is included because none was supplied. Verify that event's automation and AI rules before competition use.
