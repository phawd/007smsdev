#!/bin/bash

# Phase 5: Carrier Locking Mechanism Analysis
# Focuses on understanding lock policies, NV item structure, and bypass vectors
# Emphasizes LOCKING MECHANISMS (as per user requirement)

ANALYSIS_DIR="${1:-.}/phase5_locking_analysis_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "========================================="
echo "Phase 5: Carrier Locking Analysis"
echo "========================================="
echo "Analysis directory: $ANALYSIS_DIR"
echo "Timestamp: $TIMESTAMP"
echo ""

mkdir -p "$ANALYSIS_DIR"/{nv_analysis,config_analysis,policy_analysis,spc_research}

# ============================================
# STEP 1: Get all readable NV items
# ============================================
echo "=== STEP 1: NV Item Enumeration ==="

# Extended list of NV items (18 readable per MiFi guide)
declare -a NV_ITEMS=(
  "0"     # Security Code
  "1"     # Slot Cycle Index
  "2"     # Unknown
  "3"     # Min Lock
  "10"    # Slot Cycle
  "441"   # GPS Mode
  "550"   # **IMEI (BCD)**
  "553"   # SID/NID Lock
  "946"   # Modem Config
  "947"   # SMS Config
  "1015"  # Roaming Config
  "1016"  # Roaming Config 2
  "2954"  # Band Class Pref
  "3461"  # **SIM Lock Status** ⭐
  "4399"  # **Subsidy Lock 2** ⭐
  "6828"  # Perso Status
  "6830"  # Carrier Info
  "60044" # **PRI Version (WRITABLE!)** ⭐
)

echo "Reading ${#NV_ITEMS[@]} NV items..."

for nv_id in "${NV_ITEMS[@]}"; do
  output=$(adb shell "/opt/nvtl/bin/modem2_cli nv read $nv_id" 2>&1)
  echo "$output" > "$ANALYSIS_DIR/nv_analysis/nv_item_${nv_id}.txt"
  
  # Extract and summarize critical items
  if [ "$nv_id" = "550" ]; then
    echo "NV 550 (IMEI): $(echo "$output" | head -1)"
  elif [ "$nv_id" = "3461" ]; then
    echo "NV 3461 (SIM Lock): $(echo "$output" | head -1)"
  elif [ "$nv_id" = "4399" ]; then
    echo "NV 4399 (Subsidy Lock): $(echo "$output" | head -1)"
  elif [ "$nv_id" = "60044" ]; then
    echo "NV 60044 (PRI - WRITABLE): $(echo "$output" | head -1)"
  fi
done

echo "NV analysis complete."
echo ""

# ============================================
# STEP 2: Analyze Configuration Files
# ============================================
echo "=== STEP 2: Configuration File Analysis ==="

# Carrier customization (defines lock policies!)
echo "Analyzing carrier customization XML..."
adb shell "cat /opt/nvtl/etc/cc/carrier_customization.xml" \
  > "$ANALYSIS_DIR/config_analysis/carrier_customization.xml"

# Extract lock-related settings
echo "Lock-related settings found:"
adb shell "grep -i 'lock\|subsidy\|sim\|spc\|pin' /opt/nvtl/etc/cc/carrier_customization.xml" \
  2>/dev/null | head -20 > "$ANALYSIS_DIR/config_analysis/lock_keywords.txt" || \
  echo "No direct lock keywords in carrier customization" > "$ANALYSIS_DIR/config_analysis/lock_keywords.txt"

# Settings configuration
adb shell "cat /opt/nvtl/etc/settings/config.xml" \
  > "$ANALYSIS_DIR/config_analysis/settings.xml"

echo "Config analysis complete."
echo ""

# ============================================
# STEP 3: Analyze FOTA Mechanism (Lock Enforcement)
# ============================================
echo "=== STEP 3: FOTA Mechanism Analysis ==="

# FOTA implements upgrade-only policy (prevents downgrade to unlock)
echo "Extracting FOTA history..."
adb shell "cat /opt/nvtl/data/fota/history.bin" \
  > "$ANALYSIS_DIR/policy_analysis/fota_history.bin" 2>/dev/null || \
  echo "Binary file, attempted extraction"

adb shell "cat /opt/nvtl/data/fota/update_log" \
  > "$ANALYSIS_DIR/policy_analysis/fota_update_log.txt" 2>/dev/null

# Analyze FOTA certificate chain
echo "FOTA certificates (signature verification):"
adb shell "cat /opt/nvtl/etc/fota/build_cert.pem" \
  > "$ANALYSIS_DIR/policy_analysis/fota_build_certificate.pem"

adb shell "cat /opt/nvtl/etc/fota/device.pem" \
  > "$ANALYSIS_DIR/policy_analysis/fota_device_certificate.pem"

echo "FOTA mechanism analysis complete."
echo ""

# ============================================
# STEP 4: Research Summary
# ============================================
echo "=== STEP 4: Summary ==="

cat > "$ANALYSIS_DIR/LOCKING_RESEARCH_SUMMARY.txt" << 'RESEARCH_SUMMARY'
PHASE 5 LOCKING MECHANISM RESEARCH
===================================

KEY FINDINGS:

1. MULTI-LAYER LOCK ARCHITECTURE
   - SIM Lock (NV 3461): IMSI whitelist
   - Subsidy Lock (NV 4399): Carrier network approval
   - PRI Version (NV 60044): WRITABLE without SPC (Phase 4 finding)
   - EFS2 Firmware: SPC hash storage (active protection)

2. CRITICAL NV ITEMS MAPPED:
   - NV 3461: SIM Lock Status (protected, requires SPC)
   - NV 4399: Subsidy Lock Status (protected)
   - NV 60044: PRI Version (WRITABLE without SPC!)
   - NV 550: IMEI (readable, BCD encoded)

3. FOTA LOCK ENFORCEMENT:
   - Updates must be signed by Verizon
   - Downgrade policy enforced
   - Certificates extracted for analysis

4. BYPASS VECTORS:
   - Vector 1: PRI version manipulation (Phase 4)
   - Vector 2: NV item direct write (protected)
   - Vector 3: Firmware patching (EDL required)
   - Vector 4: FOTA downgrade
   - Vector 5: FOTA MITM attack

NEXT STEPS: Binary analysis of libmodem2_api.so
RESEARCH_SUMMARY

echo ""
echo "========================================="
echo "Locking Analysis Complete!"
echo "========================================="
echo "Analysis directory: $ANALYSIS_DIR"
echo ""
