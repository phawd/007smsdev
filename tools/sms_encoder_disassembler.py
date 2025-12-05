#!/usr/bin/env python3
"""
Phase 6B: SMS Encoder Disassembly Tool
Disassembles key SMS encoding/decoding functions from libsms_encoder.so
"""

import json
import sys
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install pyelftools capstone")
    sys.exit(1)

# Key SMS functions to analyze
SMS_TARGET_FUNCTIONS = [
    # PDU encoding (GSM)
    "PDU_Encode_Sms",
    "PDU_Decode_Sms",
    "PDU_Decode_Sms_Deliver",
    "PDU_Decode_Sms_Submit",
    
    # CDMA encoding
    "CDMA_Encode_Message",
    "CDMA_Encode_Message_IS637",
    "CDMA_Decode_Message",
    "CDMA_Decode_Message_IS637",
    "CDMA_Decode_BearerData",
    
    # High-level encode
    "EncodeSms",
    "EncodeSmsEx",
    "SmsEncodeMessage",
    "SmsEncodeMessageEx",
    
    # Address encoding
    "Encode_Address",
    "Encode_UserData",
    "Encode_MessageId",
    "Encode_Callback",
    
    # WMS transport layer
    "wms_ts_encode_submit",
    "wms_ts_encode_deliver",
    "wms_ts_encode_CDMA_tl",
    "wms_ts_decode_CDMA_tl",
    
    # Character encoding
    "wms_ts_pack_gw_7_bit_chars",
    "wms_ts_unpack_gw_7_bit_chars",
    "wms_ts_ucs2_to_gsm",
    "wms_ts_ascii_to_bcd",
]


def disassemble_function(binary_data: bytes, address: int, size: int, func_name: str) -> dict:
    """Disassemble a function and analyze its structure."""
    
    # Try ARM mode first, then Thumb
    for mode, mode_name in [(CS_MODE_ARM, "ARM"), (CS_MODE_THUMB, "THUMB")]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        
        instructions = []
        call_targets = []
        string_refs = []
        data_refs = []
        
        for insn in md.disasm(binary_data[address:address+size], address):
            instr_data = {
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex()
            }
            instructions.append(instr_data)
            
            # Track function calls
            if insn.mnemonic in ['bl', 'blx', 'b']:
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    call_targets.append({
                        "from": hex(insn.address),
                        "target": hex(target),
                        "type": insn.mnemonic
                    })
                except ValueError:
                    pass
            
            # Track memory loads (potential string/data refs)
            if insn.mnemonic in ['ldr', 'adr']:
                if 'pc' in insn.op_str:
                    data_refs.append({
                        "address": hex(insn.address),
                        "instruction": f"{insn.mnemonic} {insn.op_str}"
                    })
        
        if instructions:
            return {
                "name": func_name,
                "address": hex(address),
                "size": size,
                "mode": mode_name,
                "instruction_count": len(instructions),
                "call_targets": call_targets,
                "data_refs": data_refs[:10],  # Limit to first 10
                "instructions": instructions[:50],  # First 50 instructions
                "prologue": instructions[:5] if instructions else [],
                "epilogue": instructions[-5:] if len(instructions) >= 5 else instructions
            }
    
    return {"name": func_name, "error": "Failed to disassemble"}


def analyze_sms_encoder(library_path: str) -> dict:
    """Analyze SMS encoder library and disassemble key functions."""
    
    results = {
        "library": library_path,
        "analysis_type": "Phase 6B SMS Encoder Analysis",
        "target_functions": [],
        "all_sms_functions": [],
        "encoding_flow": {},
        "summary": {}
    }
    
    with open(library_path, 'rb') as f:
        binary_data = f.read()
        f.seek(0)
        elf = ELFFile(f)
        
        symtab = elf.get_section_by_name('.symtab')
        if not symtab:
            symtab = elf.get_section_by_name('.dynsym')
        
        if not symtab:
            return {"error": "No symbol table found"}
        
        # Build function map
        func_map = {}
        for sym in symtab.iter_symbols():
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value'] > 0:
                func_map[sym.name] = {
                    'address': sym['st_value'],
                    'size': sym['st_size']
                }
        
        # Find all SMS-related functions
        sms_keywords = ['sms', 'pdu', 'cdma', 'gsm', 'wms', 'encode', 'decode', 'message']
        for name, info in func_map.items():
            if any(kw in name.lower() for kw in sms_keywords):
                results["all_sms_functions"].append({
                    "name": name,
                    "address": hex(info['address']),
                    "size": info['size']
                })
        
        # Disassemble target functions
        for func_name in SMS_TARGET_FUNCTIONS:
            if func_name in func_map:
                info = func_map[func_name]
                print(f"Disassembling {func_name} @ {hex(info['address'])} (size={info['size']})")
                
                disasm = disassemble_function(
                    binary_data, 
                    info['address'], 
                    info['size'], 
                    func_name
                )
                results["target_functions"].append(disasm)
        
        # Map encoding flow
        results["encoding_flow"] = {
            "gsm_pdu_chain": [
                "SmsEncodeMessage -> EncodeSms -> PDU_Encode_Sms",
                "PDU_Encode_Sms -> wms_ts_encode_submit -> wms_ts_pack_gw_7_bit_chars"
            ],
            "cdma_chain": [
                "SmsEncodeMessage -> CDMA_Encode_Message_IS637",
                "CDMA_Encode_Message -> wms_ts_encode_CDMA_tl -> Encode_UserData"
            ],
            "decode_chain": [
                "wms_ts_decode -> PDU_Decode_Sms / CDMA_Decode_Message",
                "PDU_Decode_Sms -> PDU_Decode_Sms_Deliver / PDU_Decode_Sms_Submit"
            ]
        }
        
        results["summary"] = {
            "total_sms_functions": len(results["all_sms_functions"]),
            "disassembled_count": len(results["target_functions"]),
            "pdu_encode_size": func_map.get("PDU_Encode_Sms", {}).get('size', 0),
            "cdma_encode_size": func_map.get("CDMA_Encode_Message_IS637", {}).get('size', 0),
        }
    
    return results


def main():
    library_path = "mifi_backup/proprietary_analysis/libraries_full/lib/libsms_encoder.so"
    output_path = "mifi_backup/proprietary_analysis/SMS_ENCODER_DISASSEMBLY.json"
    
    # Check for custom paths
    if len(sys.argv) > 1:
        library_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
    
    if not Path(library_path).exists():
        print(f"Library not found: {library_path}")
        sys.exit(1)
    
    print("=" * 70)
    print("Phase 6B: SMS Encoder Disassembly Analysis")
    print("=" * 70)
    
    results = analyze_sms_encoder(library_path)
    
    # Save results
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    # Print summary
    print("\n" + "=" * 70)
    print("SMS Encoder Analysis Summary")
    print("=" * 70)
    print(f"Total SMS Functions: {results['summary'].get('total_sms_functions', 0)}")
    print(f"Disassembled Functions: {results['summary'].get('disassembled_count', 0)}")
    print(f"PDU_Encode_Sms size: {results['summary'].get('pdu_encode_size', 0)} bytes")
    print(f"CDMA_Encode_Message_IS637 size: {results['summary'].get('cdma_encode_size', 0)} bytes")
    
    print("\n--- Encoding Flow ---")
    for chain_type, chains in results.get("encoding_flow", {}).items():
        print(f"\n{chain_type}:")
        for chain in chains:
            print(f"  {chain}")
    
    print("\n--- Disassembled Functions ---")
    for func in results.get("target_functions", [])[:10]:
        print(f"  {func.get('name', 'unknown'):40} @ {func.get('address', '?'):10} "
              f"({func.get('instruction_count', 0)} instructions, {func.get('mode', '?')} mode)")


if __name__ == "__main__":
    main()
