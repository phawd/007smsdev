NCK & SPC Ghidra/Disassembly Analysis
=====================================

Summary
-------
This document summarizes the evidence from Ghidra/Rizin decompilation and disassembly that identify
how the baseband reads the master NCK (NV 0xEA64 / 60004) and validates SPC/NCK verification.

Key Findings
------------
- The function modem2_modem_carrier_unlock() in libmal_qct or libmodem2 reads NV 0xEA64 (60004) and compares
  the stored NCK (104 bytes) with the user-supplied NCK using a plain strcmp/strncmp (no hashing).

- Relevant functions found in disassembly and analysis artifacts:
  - modem2_modem_carrier_unlock (unlock/compare, writes lock flags 0xEAAC and 0xEA62 on success)
  - modem2_validate_spc_code (SPC validation entry point, called via modem2_cli validate_spc)
  - nwqmi_dms_validate_spc (QMI DMS path to SPC validation);
  - nwqmi_nvtl_nv_item_read_cmd(nv_id, buf, size) calls to read NV values from storage.

- Evidence (repo artifacts):
  - docs/ARCHITECTURE_DIAGRAM.md documents NV 0xEA64 reading: "Read NV 0xEA64 (master NCK, 104 bytes, PLAINTEXT!)"
  - mifi_backup/proprietary_analysis/libraries/PHASE6A_DISASSEMBLY_ANALYSIS.json contains entries for
    modem2_modem_carrier_unlock with operand usages referencing NV 0xEA64, 0xEAAC, and 0xEA62 (r0, #0xea64).
  - forensic reports indicate a 104-byte NCK is read and compared (strncmp length 104).

Implications
------------
- The baseband stores the master NCK as plaintext in NV 0xEA64 (60004 decimal). This is a security risk if
  the device or backups containing the NV item are compromised.

- The unlock process compares user-supplied code with the stored NCK directly; therefore, a read-only tool that
  displays the NCK can reveal the full unlock code.

- Because there are multiple NV lock flags (0xEAAC, 0xEA62) that are written on success, write operations are
  dangerous and must continue to require explicit gating and backups before modification.

Paths/Patterns
-------------
- NV item IDs: 0xEA64 (decimal 60004), 0xEAAC, 0xEA62 (lock flags), 60044 (PRI version)
- Common QMI commands used in device: `nwcli qmi_idl read_nv <nv_id> <index>` and `modem2_cli` wrapper commands
  for validation and unlock.

Suggested Actions
-----------------
- Implement a read-only `show-nck` command to view the master NCK in a masked form by default; reveal of full
  NCK must be gated with explicit confirmation (and command-line `--danger-do-it`) to avoid accidental disclosure.

- Before any NV write/rollback operations, always create a local backup under tools/backups and document the
  backup and recovery steps in a PHASE file.

- Update documentation and PR guidelines for modifications that touch NV write flows and add tests and
  instrumentation to ensure `nv_write` isn't used accidentally.

References
----------
- repo/mifi_backup/proprietary_analysis/PHASE6A_DISASSEMBLY_ANALYSIS.json (see references to NV IDs and operands)
- docs/ARCHITECTURE_DIAGRAM.md

If you want, I can add more automated cross-checks into our tooling (e.g., detect NV 0xEA64 presence on device and
fail-safe on write attempts) or add more robust decompilation extraction from the PHASE6 JSON files.
