#!/usr/bin/env python3
"""
ELF Symbol Extractor for ARM Binaries
Phase 6A: Automated symbol extraction from MiFi proprietary libraries
"""

import os
import sys
import json
import struct
from pathlib import Path
from collections import defaultdict

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.relocation import RelocationSection
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False
    print("Warning: pyelftools not installed. Using fallback parsing.")

class ELFSymbolExtractor:
    """Extract and analyze symbols from ARM ELF binaries"""
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.symbols = []
        self.dynamic_symbols = []
        self.relocations = []
        self.strings = []
        self.metadata = {}
        
    def extract_all(self) -> dict:
        """Extract all symbol information from the ELF file"""
        if HAS_ELFTOOLS:
            return self._extract_with_elftools()
        else:
            return self._extract_fallback()
    
    def _extract_with_elftools(self) -> dict:
        """Extract using pyelftools library"""
        with open(self.filepath, 'rb') as f:
            elf = ELFFile(f)
            
            # Basic metadata
            self.metadata = {
                'filename': self.filepath.name,
                'arch': elf.header.e_machine,
                'bits': elf.elfclass,
                'endian': 'little' if elf.little_endian else 'big',
                'type': elf.header.e_type,
                'entry': hex(elf.header.e_entry),
                'sections': []
            }
            
            # Extract section info
            for section in elf.iter_sections():
                self.metadata['sections'].append({
                    'name': section.name,
                    'type': section['sh_type'],
                    'addr': hex(section['sh_addr']),
                    'size': section['sh_size']
                })
            
            # Extract symbol tables
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        sym_info = {
                            'name': symbol.name,
                            'value': hex(symbol['st_value']),
                            'size': symbol['st_size'],
                            'type': symbol['st_info']['type'],
                            'bind': symbol['st_info']['bind'],
                            'visibility': symbol['st_other']['visibility'],
                            'section': symbol['st_shndx'],
                            'table': 'dynsym' if '.dynsym' in section.name else 'symtab'
                        }
                        
                        if section.name == '.dynsym':
                            self.dynamic_symbols.append(sym_info)
                        else:
                            self.symbols.append(sym_info)
                
                # Extract relocations
                if isinstance(section, RelocationSection):
                    for reloc in section.iter_relocations():
                        self.relocations.append({
                            'offset': hex(reloc['r_offset']),
                            'type': reloc['r_info_type'],
                            'symbol': reloc['r_info_sym']
                        })
            
        return self._compile_results()
    
    def _extract_fallback(self) -> dict:
        """Fallback parsing without elftools"""
        with open(self.filepath, 'rb') as f:
            data = f.read()
        
        # Basic ELF header parsing
        if data[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF file")
        
        self.metadata = {
            'filename': self.filepath.name,
            'bits': 32 if data[4] == 1 else 64,
            'endian': 'little' if data[5] == 1 else 'big'
        }
        
        # Extract printable strings (basic strings analysis)
        self._extract_strings(data)
        
        return self._compile_results()
    
    def _extract_strings(self, data: bytes, min_length: int = 4):
        """Extract printable strings from binary"""
        current = []
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    self.strings.append(''.join(current))
                current = []
        if len(current) >= min_length:
            self.strings.append(''.join(current))
    
    def _compile_results(self) -> dict:
        """Compile all extracted data into a structured result"""
        # Filter for SPC/unlock related items
        spc_keywords = ['spc', 'unlock', 'carrier', 'validate', 'nv_', 'dms_', 'lock', 'imei']
        
        def is_relevant(name: str) -> bool:
            name_lower = name.lower()
            return any(kw in name_lower for kw in spc_keywords)
        
        relevant_symbols = [s for s in self.dynamic_symbols if is_relevant(s['name'])]
        all_functions = [s for s in self.dynamic_symbols if s['type'] == 'STT_FUNC' and s['name']]
        
        return {
            'metadata': self.metadata,
            'total_dynamic_symbols': len(self.dynamic_symbols),
            'total_symbols': len(self.symbols),
            'total_relocations': len(self.relocations),
            'spc_related_symbols': relevant_symbols,
            'all_exported_functions': [
                {'name': s['name'], 'address': s['value'], 'size': s['size']}
                for s in all_functions if s['bind'] == 'STB_GLOBAL'
            ],
            'function_categories': self._categorize_functions(all_functions)
        }
    
    def _categorize_functions(self, functions: list) -> dict:
        """Categorize functions by their prefix/purpose"""
        categories = defaultdict(list)
        
        for func in functions:
            name = func['name']
            if not name:
                continue
                
            # Categorize by prefix
            if name.startswith('nwqmi_'):
                categories['qmi_interface'].append(name)
            elif name.startswith('modem2_'):
                categories['modem_control'].append(name)
            elif name.startswith('dsm_'):
                categories['data_service'].append(name)
            elif name.startswith('fota_'):
                categories['firmware_update'].append(name)
            elif name.startswith('sms_'):
                categories['sms_functions'].append(name)
            elif name.startswith('nv_'):
                categories['nv_item_access'].append(name)
            elif 'carrier' in name.lower():
                categories['carrier_functions'].append(name)
            elif 'spc' in name.lower():
                categories['spc_functions'].append(name)
            elif 'unlock' in name.lower():
                categories['unlock_functions'].append(name)
        
        return dict(categories)


def analyze_library(filepath: str) -> dict:
    """Analyze a single library file"""
    extractor = ELFSymbolExtractor(filepath)
    return extractor.extract_all()


def analyze_all_libraries(lib_dir: str) -> dict:
    """Analyze all .so files in a directory"""
    results = {}
    lib_path = Path(lib_dir)
    
    for so_file in lib_path.glob('*.so'):
        print(f"Analyzing {so_file.name}...")
        try:
            results[so_file.name] = analyze_library(str(so_file))
        except Exception as e:
            results[so_file.name] = {'error': str(e)}
    
    return results


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ELF Symbol Extractor for ARM binaries')
    parser.add_argument('path', help='Path to .so file or directory containing .so files')
    parser.add_argument('-o', '--output', help='Output JSON file', default='symbols_analysis.json')
    parser.add_argument('--filter', help='Filter symbols by keyword', default=None)
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    path = Path(args.path)
    
    if path.is_file():
        results = {path.name: analyze_library(str(path))}
    elif path.is_dir():
        results = analyze_all_libraries(str(path))
    else:
        print(f"Error: {path} not found")
        sys.exit(1)
    
    # Filter if requested
    if args.filter:
        keyword = args.filter.lower()
        for lib_name, lib_data in results.items():
            if 'all_exported_functions' in lib_data:
                lib_data['filtered_functions'] = [
                    f for f in lib_data['all_exported_functions']
                    if keyword in f['name'].lower()
                ]
    
    # Output
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nAnalysis complete. Results saved to {output_path}")
    
    # Print summary
    for lib_name, lib_data in results.items():
        if 'error' in lib_data:
            print(f"\n{lib_name}: Error - {lib_data['error']}")
            continue
            
        print(f"\n{'='*60}")
        print(f"Library: {lib_name}")
        print(f"{'='*60}")
        print(f"Total dynamic symbols: {lib_data.get('total_dynamic_symbols', 'N/A')}")
        print(f"Total exported functions: {len(lib_data.get('all_exported_functions', []))}")
        
        if lib_data.get('spc_related_symbols'):
            print(f"\nSPC-Related Symbols ({len(lib_data['spc_related_symbols'])}):")
            for sym in lib_data['spc_related_symbols']:
                print(f"  - {sym['name']} @ {sym['value']} (type: {sym['type']})")
        
        if lib_data.get('function_categories'):
            print(f"\nFunction Categories:")
            for cat, funcs in lib_data['function_categories'].items():
                print(f"  {cat}: {len(funcs)} functions")
                if args.verbose:
                    for f in funcs[:5]:
                        print(f"    - {f}")
                    if len(funcs) > 5:
                        print(f"    ... and {len(funcs) - 5} more")


if __name__ == '__main__':
    main()
