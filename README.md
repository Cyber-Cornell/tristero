# Tristero

> [The Tristero](https://en.wikipedia.org/wiki/The_Crying_of_Lot_49) is a secret postal
> network that carries messages under the nose of the official mail, dreamed up by Thomas
> Pynchon, Cornell class of '59. Cyber@Cornell's Tristero is our own quiet courier service:
> a master agent passes orders to a network of worker agents and they report back, while the
> students keep the official business moving.

https://github.com/user-attachments/assets/c9720614-a93e-4e48-b472-12e9f5fb339c

*Demo (35s, click to play): the master hands worker-2 a fake weather API and worker-1 a web
page that consumes it, then waits for both.*

## Orchestration (MVP)

A master OpenCode agent splits work across worker OpenCode agents. Each agent runs on its own
Ubuntu 24.04 Desktop VM, and a student sits at each desktop to watch and steer it.

```
master VM                                     worker VMs
  opencode (agent: master)                      opencode serve :4096 (agent: worker)
    └─ shell tool ── fleet ──────────HTTP──►   systemd service, runs as the desktop user
                                                  student: tristero-attach to watch / take over
```

- **Workers** run `opencode serve` behind a per-worker password. Agents run as the desktop
  user, who has passwordless sudo, so they can install tools and run any command.
- **The master** delegates work on worker machines through `fleet`, and can run any command
  on its own VM (passwordless sudo) to check results or use tools.
- **`fleet`** (`bin/fleet`) is the whole orchestration API: `workers`, `send`, `wait`, `read`,
  `log`, `stop`, plus `add`/`remove` for the roster (students only; the master is denied these).
  Each worker gets one long-lived session, so it remembers earlier tasks.
- Model: `opencode/deepseek-v4.1-flash-free` (anonymous, free) by default. To use another
  provider (e.g. the Z.AI coding plan), connect it on each machine (`/connect` in OpenCode),
  then rerun provision with `TRISTERO_MODEL=zai-coding-plan/glm-5.3`. Reruns keep the
  model a machine already has. Existing worker sessions keep their model; `fleet add` the
  worker again to start a fresh session.

## Set up real machines

Install Ubuntu 24.04 Desktop in a VM, log in as your normal user, get this repo, then:

```bash
sudo ./provision worker worker-1    # on each worker; name defaults to the hostname
sudo ./provision master             # on the master
```

Each worker prints its URL, password, and a ready-made line. Paste that line into a terminal
on the master:

```bash
fleet add worker-1 http://192.168.1.23:4096 <password>
fleet workers
```

Then on the master, open **Tristero master** from the app menu, or run `cd ~ && opencode`,
and give it a job, for example "Have each worker report its listening ports and harden SSH."

The master must reach each worker on TCP 4096, so use bridged networking (or port forwarding)
when the VMs are on different laptops.

## Steer or override a worker

On the worker's desktop, open **Tristero worker agent** (or run `tristero-attach`). That's the
normal OpenCode TUI connected to the worker's own server, showing the session the master is
driving. Each worker has exactly one such session, titled **tristero**; `fleet` and
`tristero-attach` both find it by name (whichever runs first creates it), so open it before or
after giving the master a task. Tasks then appear in it live. Interrupt it with Esc, type new instructions, or carry on by hand in a terminal. The
worker's prompt says a student's instructions override the master's. The master sees the
result through `fleet read`.

From the master side: `fleet stop <worker>` interrupts, `fleet log <worker>` shows every
command the worker ran.

## Test lab on this laptop (libvirt/KVM)

```bash
lab/lab up          # 1 master + 2 workers (TRISTERO_WORKERS=N), ~10-15 min first time
lab/lab status      # IPs and the desktop login
lab/lab view worker-1                 # open the desktop (SPICE)
lab/lab ssh master fleet workers      # or a shell: lab/lab ssh master
lab/lab deploy      # re-copy the repo and rerun ./provision after editing it
lab/lab down        # delete the tr-* VMs (add --all to also drop the base image)
```

`lab up` uses Ubuntu cloud images plus `ubuntu-desktop-minimal` as a stand-in for a Desktop
install, then runs `./provision` over SSH exactly as a student would and pastes each
`fleet add` line into the master. VMs get 2 vCPU, 3 GB RAM, and a 20 GB thin disk. State
(SSH key, desktop password) lives in `.tools/lab/`.

Try it from the master:

```bash
lab/lab ssh master
opencode run "Have every worker report hostname, kernel, and listening ports, then summarize."
opencode run "Install nginx on worker-1 only and confirm it serves on port 80."
```

## Known quirks

- OpenCode's free models reject requests from an agent with no `read` tool (HTTP 429,
  reported as "Free usage limit reached"). Keep `read` allowed if you restrict an agent.
- A real free-tier limit gives the same error. All lab VMs share the host's public IP, so if
  it persists, switch models with `TRISTERO_MODEL=opencode/<model> lab/lab deploy`.

## Not built yet

Shared tool install (`install_tools` in `provision` is a stub), skills and playbooks, remote
targets over SSH/WinRM, shared discussion board, credential manager, scoreboard monitoring,
injects, and TLS between master and workers.
