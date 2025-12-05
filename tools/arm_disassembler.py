#!/usr/bin/env python3
"""
ARM Binary Disassembler and SPC Algorithm Analyzer
Phase 6A: Automated disassembly of MiFi proprietary libraries
"""

import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("Warning: Capstone not installed. Disassembly unavailable.")


class ARMDisassembler:
    """Disassemble ARM binary functions"""
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.elf = None
        self.code_section = None
        self.symbols = {}
        self._load_elf()
    
    def _load_elf(self):
        """Load ELF file and extract info"""
        self.file_handle = open(self.filepath, 'rb')
        self.elf = ELFFile(self.file_handle)
        
        # Get code section
        self.text_section = self.elf.get_section_by_name('.text')
        if self.text_section:
            self.code_data = self.text_section.data()
            self.code_base = self.text_section['sh_addr']
        
        # Build symbol map
        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value'] > 0:
                        self.symbols[sym.name] = {
                            'address': sym['st_value'],
                            'size': sym['st_size'],
                            'bind': sym['st_info']['bind']
                        }
    
    def disassemble_function(self, func_name: str, max_instructions: int = 100) -> dict:
        """Disassemble a specific function by name"""
        if not HAS_CAPSTONE:
            return {'error': 'Capstone not installed'}
        
        if func_name not in self.symbols:
            return {'error': f'Function {func_name} not found'}
        
        func_info = self.symbols[func_name]
        addr = func_info['address']
        size = func_info['size'] or 256  # Default size if not specified
        
        # Calculate offset in file
        offset = addr - self.code_base
        if offset < 0 or offset >= len(self.code_data):
            return {'error': f'Invalid offset {hex(offset)} for {func_name}'}
        
        code = self.code_data[offset:offset + size]
        
        # Determine ARM or Thumb mode (bit 0 of address indicates Thumb)
        if addr & 1:
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            addr = addr & ~1  # Clear Thumb bit
        else:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        
        md.detail = True
        
        instructions = []
        for i, insn in enumerate(md.disasm(code, addr)):
            if i >= max_instructions:
                break
            
            # Resolve symbols for branch targets
            target_sym = None
            if insn.mnemonic.startswith('b') and insn.op_str:
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    for sym_name, sym_info in self.symbols.items():
                        if sym_info['address'] == target or sym_info['address'] == target + 1:
                            target_sym = sym_name
                            break
                except:
                    pass
            
            inst_data = {
                'address': hex(insn.address),
                'bytes': insn.bytes.hex(),
                'mnemonic': insn.mnemonic,
                'operands': insn.op_str,
            }
            if target_sym:
                inst_data['target_symbol'] = target_sym
            
            instructions.append(inst_data)
            
            # Stop at return instructions
            if insn.mnemonic in ['bx', 'pop'] and 'pc' in insn.op_str.lower():
                break
        
        return {
            'function': func_name,
            'address': hex(func_info['address']),
            'size': size,
            'instructions': instructions,
            'instruction_count': len(instructions)
        }
    
    def analyze_spc_functions(self) -> dict:
        """Analyze all SPC-related functions"""
        spc_keywords = ['spc', 'unlock', 'carrier', 'validate', 'imei', 'nv_']
        
        results = {
            'library': self.filepath.name,
            'functions': {}
        }
        
        for func_name in self.symbols:
            if any(kw in func_name.lower() for kw in spc_keywords):
                disasm = self.disassemble_function(func_name)
                results['functions'][func_name] = disasm
        
        return results
    
    def get_function_call_graph(self, func_name: str) -> dict:
        """Get functions called by a specific function"""
        disasm = self.disassemble_function(func_name, max_instructions=200)
        
        if 'error' in disasm:
            return disasm
        
        calls = []
        for insn in disasm.get('instructions', []):
            if insn['mnemonic'] in ['bl', 'blx']:
                target = insn.get('target_symbol') or insn['operands']
                calls.append({
                    'address': insn['address'],
                    'target': target
                })
        
        return {
            'function': func_name,
            'calls': calls,
            'call_count': len(calls)
        }
    
    def close(self):
        """Close file handle"""
        if self.file_handle:
            self.file_handle.close()


def analyze_spc_algorithm(lib_path: str) -> dict:
    """Main analysis of SPC algorithm in library"""
    analyzer = ARMDisassembler(lib_path)
    
    # Target functions for SPC analysis
    target_functions = [
        'modem2_modem_validate_spc',
        'modem2_modem_get_spc_validate_limit',
        'modem2_modem_carrier_unlock',
        'modem2_modem_get_carrier_unlock_status',
        'nwqmi_dms_validate_spc',
        'dsm_modem_get_imei',
        'fota_modem_write_nv_item'
    ]
    
    results = {
        'library': Path(lib_path).name,
        'target_function_analysis': {},
        'call_graphs': {}
    }
    
    for func in target_functions:
        if func in analyzer.symbols:
            results['target_function_analysis'][func] = analyzer.disassemble_function(func)
            results['call_graphs'][func] = analyzer.get_function_call_graph(func)
    
    analyzer.close()
    return results


def main():
    import sys
    
    # Primary analysis target
    lib_path = r'f:\repo\zerosms\mifi_backup\proprietary_analysis\libraries\libmal_qct.so'
    
    print("="*70)
    print("Phase 6A: SPC Algorithm Disassembly Analysis")
    print("="*70)
    
    results = analyze_spc_algorithm(lib_path)
    
    # Output results
    output_path = Path(lib_path).parent / 'PHASE6A_DISASSEMBLY_ANALYSIS.json'
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    # Print summary
    print("\n" + "="*70)
    print("Target Function Analysis Summary")
    print("="*70)
    
    for func_name, analysis in results['target_function_analysis'].items():
        if 'error' in analysis:
            print(f"\n{func_name}: {analysis['error']}")
            continue
        
        print(f"\n{func_name}")
        print(f"  Address: {analysis['address']}")
        print(f"  Instructions: {analysis['instruction_count']}")
        
        # Show first few instructions
        if analysis.get('instructions'):
            print("  First 10 instructions:")
            for insn in analysis['instructions'][:10]:
                target = f" -> {insn['target_symbol']}" if 'target_symbol' in insn else ""
                print(f"    {insn['address']}: {insn['mnemonic']} {insn['operands']}{target}")
    
    # Print call graphs
    print("\n" + "="*70)
    print("Function Call Graphs")
    print("="*70)
    
    for func_name, cg in results['call_graphs'].items():
        if 'error' in cg:
            continue
        print(f"\n{func_name} calls:")
        for call in cg['calls']:
            print(f"  {call['address']}: -> {call['target']}")


if __name__ == '__main__':
    main()
