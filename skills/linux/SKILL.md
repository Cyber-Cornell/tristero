---
name: linux
description: Harden the assigned Linux/SSSD/Nginx host while preserving scored service and AD login.
---

Use remote_execute for Bash commands. Inventory distro, privileges, Nginx configuration, systemd units, listening ports, SSH, SSSD, DNS, time sync, and domain membership before changes.

Back up edited configurations and record rollback commands. Use sudo -n; do not make commands hang for interactive passwords. Preserve the inventoried SSH recovery account and verified host key.

For Nginx, inspect the existing site and required content. Validate configuration with nginx -t before reload. Check systemctl status/is-active, listening sockets, and an HTTP request to the required endpoint. Do not replace competition content or deny scorer traffic.

For AD integration, verify realm/SSSD state, domain DNS resolution, clock sync, user resolution through getent/id, and fresh AD-backed login. Coordinate with the AD worker before changes to DNS, account policy, or shared credentials. Do not assume an AD outage is a local Linux configuration failure.

Review unnecessary exposed services, account privilege, insecure permissions, and authentication logs using the actual environment. Make justified changes individually and recheck Nginx and AD-backed login after each relevant change. Do not apply a blanket firewall deny or disable required authentication.

Use rotation tools for inventoried accounts. In the pilot, an AD user's password rotation normally needs fresh Linux login verification, not an SSSD configuration rewrite; machine/trust credentials remain untouched.
