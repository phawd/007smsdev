## Summary
- Short description of change and why it is needed.

## Files changed
- List of changed files (concise).

## Testing
- Unit tests added/updated: yes/no
- Instrumentation tests added/updated (if applicable): yes/no

## Device/Root/Modem impact
- Does this change touch device-level operations (NV/EFS/SPC/Unlock)? yes/no
- If yes, include the string `DO IT` in this PR description and add a rollback/recovery plan in `docs/PHASE_*`.

## CLI examples
- If the PR changes any CLI or tools, include sample commands to reproduce the behavior.

## Safety checklist (required for device ops)
- [ ] Confirmed backups (IMEI, EFS, NV) are recorded.
- [ ] Recovery/rollback steps documented in `docs/PHASE_*`.
- [ ] Interactive runtime guard `--danger-do-it` added to tools for destructive operations.

## Notes
- Any additional context, links to documentation, or special instructions for reviewers.

# Pull Request Template

<!-- PR Template for device-safe development -->

## Summary

- Short summary of changes:

## Files changed

- List of files changed and reason:

## Tests

- Unit tests added/updated (yes/no):
- Instrumentation tests added/updated (yes/no):

## Device / NV operations

- Does this PR touch device/NV/SPC/unlock flows? (yes/no):
- If YES: include a safety plan and sign-off here.


Authorization for dangerous operations (if required):

- Add line **DO IT** below if you explicitly authorize NV writes/unlocks or SPC validation for this PR (this MUST be provided by a human):

DO IT: ________

## Testing steps

- How to reproduce locally (commands, expected results):

## Notes

- Other considerations, roll-back plan, and documentation updates:
