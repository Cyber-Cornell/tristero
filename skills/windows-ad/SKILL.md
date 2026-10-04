---
name: windows-ad
description: Harden the assigned Windows domain controller with PowerShell while preserving AD consumers.
---

Use remote_execute for PowerShell commands. Inventory OS, domain health, DNS, time, exposed services, local/domain privileged groups, account policy, remote access, and relevant authentication/service logs.

Capture recoverable configuration and policy state before edits. Confirm required authentication and management access. Coordinate with the Linux worker before changing account policy, DNS, service accounts, or network access.

Review privileged memberships, unnecessary exposure, auditing, and password policy against the task's requirements. Preserve scoring accounts and required Windows services. Avoid domain-wide policy changes until their concrete effects on consumers are understood and discussed.

Use rotation tools only for explicitly inventoried AD users or local Windows accounts. The issuer applies the prepared password once. Verify fresh remote authentication with the new password, wait for every declared consumer's successful verification, then commit. Do not perform bulk resets, krbtgt resets, trust-account resets, or remove unknown accounts.

Record domain/DNS checks, required service health, and actual consumer verification operation IDs. Report incomplete checks as incomplete; successful PowerShell execution alone does not prove end-to-end service health.
