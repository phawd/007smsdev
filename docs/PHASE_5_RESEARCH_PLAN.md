# Phase 5: Advanced Carrier Unlock Research Plan

**Objective:** Deep-dive analysis of carrier lock mechanisms, FOTA process, and SPC bypass techniques

**Status:** Initialization and tool setup

---

## Executive Overview

Phase 5 focuses on three critical areas:

1. **Locking Mechanisms** - Complete analysis of carrier lock implementation and protection layers
2. **FOTA (Firmware Over-The-Air)** - Study firmware update process, signature validation, and potential bypasses
3. **Filesystem & Binary Analysis** - Extract device filesystem and analyze ARM binaries for SPC codes and bypass vectors

---

## Phase 5 Components

### A. Filesystem Extraction & Backup

**Goal:** Create complete archive of device filesystem for offline analysis

**Files:**

- `tools/phase5_filesystem_extraction.sh` - Comprehensive MTD partition extraction
- Deliverable: Backup of all critical partitions (efs2, modem, config)

**Key Data:**

- EFS2 partition (carrier lock storage)
- Modem firmware
- Device configuration files
- FOTA update mechanism
- NV items related to carrier lock

### B. Carrier Lock Analysis

**Goal:** Document all carrier lock mechanisms and protection layers

**Files:**

- `tools/phase5_carrier_lock_analysis.sh` - Live device analysis script
- Deliverable: Detailed documentation of lock mechanisms

**Research Areas:**

1. NV Item Protection Levels
   - Tier 1: SPC-protected items (5, 851, 4398)
   - Tier 2: Partially protected (high NV items)
   - Unprotected: High NV items (60000-65535)

2. Carrier Configuration Files
   - `/policyman/device_config.xml` - Capabilities
   - `/sysconf/settings.xml` - Device settings
   - `/sysconf/features.xml` - Feature flags

3. SPC Code Validation
   - Location: libmodem2_api.so
   - Implementation: Userspace validation (bypassable)
   - Protection: SPC code checking

4. Carrier Unlock Status
   - SIM lock status (NV 3461)
   - Carrier lock status (get_carrier_unlock)
   - Subsidy lock (NV 4398)

### C. FOTA Mechanism Analysis

**Goal:** Document firmware update process and identify potential bypasses

**Research Focus:**

1. FOTA Tool Location
   - `/opt/nvtl/bin/fota_cli`
   - `/opt/nvtl/bin/modem2_cli fota_*`

2. Firmware Version Management
   - Current version: `/opt/nvtl/etc/version`
   - Version check mechanism
   - Downgrade prevention

3. Update Process
   - Package verification
   - Signature validation
   - Installation mechanism
   - Rollback capability

4. Signature Verification
   - Certificates used
   - Public key location
   - Signature algorithm
   - Bypass opportunities

### D. ARM Binary Analysis

**Goal:** Extract and analyze modem binaries for SPC codes and bypass techniques

**Files:**

- `tools/phase5_download_arm_tools.sh` - Download ARM analysis tools
- `arm_analysis_tools/ida_spc_finder.py` - IDA Pro analysis script
- `arm_analysis_tools/ghidra_spc_analyzer.py` - Ghidra analysis script
- `arm_analysis_tools/analyze_arm_binary.sh` - Quick analysis wrapper

**Key Binaries:**

1. libmodem2_api.so (CRITICAL)
   - Target: modem2_validate_spc_code()
   - Search: Hardcoded SPC values
   - Goal: Identify bypass condition

2. libmal_qct.so (HIGH PRIORITY)
   - Target: QMI packet encoding
   - Search: NV write handlers
   - Goal: Direct injection opportunities

3. modem2_cli binary (HIGH PRIORITY)
   - Target: SPC validation entry point
   - Search: Command handling
   - Goal: Attack surface identification

4. libsms_encoder.so (MEDIUM PRIORITY)
   - May contain carrier-specific logic

---

## Research Timeline

### Phase 5.1: Device Analysis & Extraction (Current)

**Deliverables:**

- [x] Filesystem extraction script created
- [x] Carrier lock analysis script created
- [x] ARM analysis tools package created
- [ ] Execute filesystem extraction
- [ ] Extract all modem binaries
- [ ] Backup device configuration

**Status:** Ready for execution

### Phase 5.2: Binary Analysis (Offline)

**Deliverables:**

- [ ] SPC validation function identified
- [ ] Hardcoded SPC codes documented
- [ ] NV write function analyzed
- [ ] Protection layer bypass mapped
- [ ] FOTA signature analysis complete

**Tools Required:**

- IDA Pro (paid) or Ghidra (free)
- ARM architecture knowledge
- Reverse engineering skills

### Phase 5.3: FOTA Mechanism Research

**Deliverables:**

- [ ] Firmware update process documented
- [ ] Signature validation method identified
- [ ] Update bypass technique assessed
- [ ] Downgrade possibility evaluated

**Focus Areas:**

- Certificate pinning
- Signature algorithm (RSA, ECDSA, etc.)
- Version checking bypass
- Recovery partition analysis

### Phase 5.4: Exploit Development

**Deliverables:**

- [ ] SPC code acquisition or bypass
- [ ] Proof-of-concept carrier unlock
- [ ] Carrier lock modification script
- [ ] Complete exploitation chain documented

### Phase 5.5: ZeroSMS Integration

**Deliverables:**

- [ ] CarrierUnlockManager.kt module
- [ ] LockedDeviceTestManager.kt module
- [ ] FOTAAnalysisModule.kt
- [ ] Advanced Testing UI screen
- [ ] CLI enhancements

---

## Critical Research Questions

### 1. SPC Code Discovery

- Is there a hardcoded SPC code in firmware?
- What's the default SPC for MiFi 8800L?
- Can SPC validation be bypassed without the code?

### 2. NV Item Protection

- Why are high NV items (>60000) unprotected?
- Is this intentional or design flaw?
- Can protection be circumvented?

### 3. Userspace Validation Bypass

- Can we inject QMI packets directly to SMD channel?
- What happens if we bypass nwcli SPC check?
- Does modem firmware re-validate?

### 4. FOTA Update Process

- Can old firmware be downgraded?
- What prevents downgrade?
- Can firmware be modified post-extraction?

### 5. Carrier Lock Persistence

- Where is carrier lock flag stored?
- Is it in EFS2 or NV items?
- Can it be directly modified?

---

## Expected Findings & Impact

### Best Case Scenario

- Hardcoded SPC code found (e.g., "090001")
- Direct carrier unlock possible
- FOTA downgrade to old firmware enabled
- Complete device unlock achieved

### Medium Case

- SPC validation bypassed via QMI injection
- Carrier lock modifiable via EFS partition
- Firmware signing key compromised
- Partial device unlock

### Realistic Case

- SPC code not found (or protected)
- Complex validation chain identified
- Multiple protection layers documented
- Phased exploitation required

---

## Ethical & Legal Considerations

### Research Protection

- ✅ DMCA § 1201(f) - Security research exemption
- ✅ Device ownership - Personal testing permitted
- ✅ Responsible disclosure - Document findings

### Constraints

- ⚠️ Device warranty void if unlocked
- ⚠️ May violate carrier terms of service
- ⚠️ Potential CFAA implications if unauthorized

### Recommended Approach

1. Document all findings privately
2. Verify reproducibility on personal device
3. Contact manufacturer/carrier through responsible disclosure
4. Allow 90-day patch window before publication

---

## Resource Requirements

### Hardware

- MiFi 8800L device (available)
- USB cable and host computer
- (Optional) USB to serial converter for direct modem access

### Software

- ADB (Android Debug Bridge) ✓
- ARM analysis tools (to download)
- IDA Pro (paid) or Ghidra (free)
- Python 3.x for scripting
- Hex editor (010 Editor recommended, or free alternatives)

### Knowledge

- ARM assembly language basics
- Qualcomm modem architecture
- QMI protocol understanding
- Reverse engineering techniques

---

## Success Criteria

**Phase 5 Success** = Achieves one or more of:

1. ✅ **SPC Code Identified** - Documented hardcoded or default SPC
2. ✅ **Bypass Technique Found** - Working method to bypass SPC validation
3. ✅ **Carrier Lock Modification** - Successfully change carrier via NV/EFS
4. ✅ **FOTA Weakness Identified** - Path to firmware modification
5. ✅ **Complete Exploitation Chain** - End-to-end carrier unlock documented

---

## Deliverables

### Documentation

- [ ] Phase 5 Findings Report
- [ ] SPC Analysis Summary
- [ ] FOTA Mechanism Documentation
- [ ] Binary Analysis Results
- [ ] Exploitation Guide

### Code

- [ ] CarrierUnlockManager.kt
- [ ] Phase 5 test harness
- [ ] Exploit script template
- [ ] ZeroSMS integration module

### Evidence

- [ ] Filesystem backup
- [ ] Binary analysis artifacts
- [ ] Proof-of-concept demonstrations
- [ ] Test results and logs

---

## Next Actions

### Immediate (Ready Now)

1. ✅ Commit Phase 4 work to git
2. ✅ Create Phase 5 analysis scripts
3. ✅ Download ARM analysis tools
4. 🔄 Execute filesystem extraction
5. 🔄 Extract modem binaries

### Short-term (This Session)

6. Analyze extracted binaries
7. Identify SPC validation function
8. Search for hardcoded SPC codes
9. Test NV item bypass vectors
10. Document FOTA process

### Medium-term (Next Session)

11. Develop carrier unlock exploit
12. Test on live device
13. Integrate into ZeroSMS platform
14. Comprehensive documentation
15. Responsible disclosure preparation

---

**Phase 5 Research Plan Complete**

Ready to proceed with device analysis and binary extraction.

---

*Last Updated: 2025-12-04*  
*Status: Planning complete, ready for execution*  
*Expected Completion: 2-3 sessions*
