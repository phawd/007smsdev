#!/usr/bin/env python3
"""
Comprehensive proprietary library analysis for MiFi 8800L
Phase 6B: Algorithm discovery and SMS process tracing
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Import pyelftools
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("Warning: Capstone not installed")


def analyze_library_algorithms(lib_path: str) -> dict:
    """Analyze library for algorithm-related functions"""
    results = {
        'library': Path(lib_path).name,
        'algorithms': [],
        'validation_functions': [],
        'encoding_functions': [],
        'nv_functions': [],
        'carrier_functions': [],
        'sms_functions': [],
        'lock_functions': [],
        'all_functions': []
    }
    
    try:
        with open(lib_path, 'rb') as f:
            elf = ELFFile(f)
            
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                    
                for sym in section.iter_symbols():
                    if sym['st_info']['type'] != 'STT_FUNC':
                        continue
                    if sym['st_value'] == 0:
                        continue
                    
                    name = sym.name
                    addr = sym['st_value']
                    size = sym['st_size']
                    
                    func_info = {
                        'name': name,
                        'address': hex(addr),
                        'size': size
                    }
                    results['all_functions'].append(func_info)
                    
                    name_lower = name.lower()
                    
                    # Algorithm detection
                    if any(kw in name_lower for kw in ['crc', 'hash', 'md5', 'sha', 'aes', 
                                                        'encrypt', 'decrypt', 'cipher', 
                                                        'checksum', 'hmac', 'derive']):
                        results['algorithms'].append(func_info)
                    
                    # Validation functions
                    if 'validate' in name_lower or 'verify' in name_lower:
                        results['validation_functions'].append(func_info)
                    
                    # Encoding functions
                    if any(kw in name_lower for kw in ['encode', 'decode', 'pack', 'unpack',
                                                        'bcd', 'pdu', 'base64', 'ucs2', 'gsm']):
                        results['encoding_functions'].append(func_info)
                    
                    # NV item functions
                    if 'nv' in name_lower and any(kw in name_lower for kw in ['read', 'write', 'item', 'get', 'set']):
                        results['nv_functions'].append(func_info)
                    
                    # Carrier functions
                    if 'carrier' in name_lower or 'sim' in name_lower:
                        results['carrier_functions'].append(func_info)
                    
                    # SMS functions
                    if 'sms' in name_lower or 'wms' in name_lower or 'cdma' in name_lower and 'message' in name_lower:
                        results['sms_functions'].append(func_info)
                    
                    # Lock/unlock functions
                    if any(kw in name_lower for kw in ['lock', 'unlock', 'spc', 'block', 'unblock']):
                        results['lock_functions'].append(func_info)
    
    except Exception as e:
        results['error'] = str(e)
    
    return results


def disassemble_function(lib_path: str, func_addr: int, func_size: int = 256) -> list:
    """Disassemble a function at given address"""
    if not HAS_CAPSTONE:
        return []
    
    instructions = []
    
    try:
        with open(lib_path, 'rb') as f:
            elf = ELFFile(f)
            
            # Find text section
            text_section = elf.get_section_by_name('.text')
            if not text_section:
                return []
            
            code_base = text_section['sh_addr']
            code_data = text_section.data()
            
            # Calculate offset
            offset = func_addr - code_base
            if offset < 0 or offset >= len(code_data):
                return []
            
            code = code_data[offset:offset + func_size]
            
            # Determine mode
            if func_addr & 1:
                md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                func_addr = func_addr & ~1
            else:
                md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            
            md.detail = True
            
            for insn in md.disasm(code, func_addr):
                instructions.append({
                    'address': hex(insn.address),
                    'mnemonic': insn.mnemonic,
                    'operands': insn.op_str,
                    'bytes': insn.bytes.hex()
                })
                
                # Stop at return
                if insn.mnemonic in ['bx', 'pop'] and 'pc' in insn.op_str.lower():
                    break
                    
                if len(instructions) >= 100:
                    break
    
    except Exception as e:
        pass
    
    return instructions


def main():
    lib_dir = Path(r'f:\repo\007smsdev\mifi_backup\proprietary_analysis\libraries_full\lib')
    output_dir = Path(r'f:\repo\007smsdev\mifi_backup\proprietary_analysis')
    
    if not lib_dir.exists():
        print(f"Library directory not found: {lib_dir}")
        return
    
    all_results = {
        'summary': {
            'total_libraries': 0,
            'total_algorithms': 0,
            'total_validation_functions': 0,
            'total_encoding_functions': 0,
            'total_nv_functions': 0,
            'total_carrier_functions': 0,
            'total_sms_functions': 0,
            'total_lock_functions': 0
        },
        'libraries': {},
        'algorithm_summary': [],
        'sms_pipeline': [],
        'carrier_unlock_pipeline': [],
        'nv_access_pipeline': []
    }
    
    # Analyze all .so files
    for lib_file in sorted(lib_dir.glob('*.so')):
        print(f"Analyzing {lib_file.name}...")
        
        result = analyze_library_algorithms(str(lib_file))
        all_results['libraries'][lib_file.name] = result
        all_results['summary']['total_libraries'] += 1
        
        # Update summaries
        all_results['summary']['total_algorithms'] += len(result.get('algorithms', []))
        all_results['summary']['total_validation_functions'] += len(result.get('validation_functions', []))
        all_results['summary']['total_encoding_functions'] += len(result.get('encoding_functions', []))
        all_results['summary']['total_nv_functions'] += len(result.get('nv_functions', []))
        all_results['summary']['total_carrier_functions'] += len(result.get('carrier_functions', []))
        all_results['summary']['total_sms_functions'] += len(result.get('sms_functions', []))
        all_results['summary']['total_lock_functions'] += len(result.get('lock_functions', []))
        
        # Collect important functions
        for algo in result.get('algorithms', []):
            all_results['algorithm_summary'].append({
                'library': lib_file.name,
                'function': algo['name'],
                'address': algo['address']
            })
        
        for sms in result.get('sms_functions', []):
            all_results['sms_pipeline'].append({
                'library': lib_file.name,
                'function': sms['name'],
                'address': sms['address']
            })
        
        for carrier in result.get('carrier_functions', []):
            if 'unlock' in carrier['name'].lower() or 'lock' in carrier['name'].lower():
                all_results['carrier_unlock_pipeline'].append({
                    'library': lib_file.name,
                    'function': carrier['name'],
                    'address': carrier['address']
                })
        
        for nv in result.get('nv_functions', []):
            all_results['nv_access_pipeline'].append({
                'library': lib_file.name,
                'function': nv['name'],
                'address': nv['address']
            })
    
    # Save results
    output_file = output_dir / 'PHASE6B_ALGORITHM_DISCOVERY.json'
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    # Print summary
    print("\n" + "="*70)
    print("PHASE 6B ANALYSIS SUMMARY")
    print("="*70)
    
    print(f"\nTotal Libraries Analyzed: {all_results['summary']['total_libraries']}")
    print(f"Algorithm Functions: {all_results['summary']['total_algorithms']}")
    print(f"Validation Functions: {all_results['summary']['total_validation_functions']}")
    print(f"Encoding Functions: {all_results['summary']['total_encoding_functions']}")
    print(f"NV Item Functions: {all_results['summary']['total_nv_functions']}")
    print(f"Carrier Functions: {all_results['summary']['total_carrier_functions']}")
    print(f"SMS Functions: {all_results['summary']['total_sms_functions']}")
    print(f"Lock/Unlock Functions: {all_results['summary']['total_lock_functions']}")
    
    if all_results['algorithm_summary']:
        print("\n--- ALGORITHM FUNCTIONS ---")
        for algo in all_results['algorithm_summary'][:20]:
            print(f"  {algo['library']}: {algo['function']} @ {algo['address']}")
    
    if all_results['sms_pipeline']:
        print("\n--- SMS PIPELINE FUNCTIONS ---")
        for sms in all_results['sms_pipeline'][:30]:
            print(f"  {sms['library']}: {sms['function']} @ {sms['address']}")
    
    if all_results['carrier_unlock_pipeline']:
        print("\n--- CARRIER UNLOCK FUNCTIONS ---")
        for carrier in all_results['carrier_unlock_pipeline'][:20]:
            print(f"  {carrier['library']}: {carrier['function']} @ {carrier['address']}")
    
    if all_results['nv_access_pipeline']:
        print("\n--- NV ITEM ACCESS FUNCTIONS ---")
        for nv in all_results['nv_access_pipeline'][:20]:
            print(f"  {nv['library']}: {nv['function']} @ {nv['address']}")


if __name__ == '__main__':
    main()
