---
name: opening
description: Inventory, verify access, and coordinate the opening CCDC lab playbook.
---

Read task_context first. Follow only the task's assigned targets and explicit requirements.

1. Inventory accounts, network interfaces, running services, authentication paths, scored endpoints, and service dependencies. Share findings in the task thread without passwords.
2. Verify current access and recovery paths. Capture configuration backups on each target with restrictive permissions before editing. Keep the existing working session while verifying new login paths.
3. For an opening rotation task, rotate only inventoried credentials marked rotate=true. Prepare the new password in the vault first. The task must include issuer and every declared consumer.
4. The issuer worker prepares and applies once, publishes the rotation ID, and verifies new authentication. Consumer workers wait for applied, run declared updates if any, and verify fresh login. The issuer commits only after every consumer verifies.
5. Applying/uncertain rotations require human reconciliation. Never regenerate passwords or retry ambiguous mutations. Never reset AD machine passwords, trust accounts, or krbtgt through this pilot.
6. Apply service-specific hardening gradually. Preserve required users, scorer access, ports, and competition functionality. Verify service and authentication behavior after changes.
7. Finish with concrete operation IDs and results. If another worker or a rotation is unfinished, continue task_context/discuss coordination or report the blockage.
