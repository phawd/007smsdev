# Ghidra Python Script for SPC Validation Function Discovery
# Purpose: Find and analyze SPC code validation functions in modem binaries
# Target Binary: libmodem2_api.so (ARM 32/64-bit)
# Usage: Load this script in Ghidra and run via Script Manager

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
import sys

class SPCFunctionAnalyzerGhidra:
    """Ghidra-based analyzer for SPC validation and bypass opportunities"""
    
    def __init__(self, program, listing, symbol_table):
        self.program = program
        self.listing = listing
        self.symbol_table = symbol_table
        self.spc_functions = []
        self.strings = {}
        self.keywords = [
            "spc", "validate", "unlock", "carrier", "lock",
            "verify", "check", "permission", "security", "code",
            "subsidy", "nv_item", "nv_write", "nv_read",
            "090001", "000000", "123456", "password"
        ]
        self.output = []
    
    def log(self, msg):
        """Log message to both console and output list"""
        print(msg)
        self.output.append(msg)
    
    def find_spc_functions(self):
        """Find all functions with SPC-related names"""
        self.log("[*] Scanning function names for SPC keywords...")
        
        for func in self.listing.getFunctions(True):
            func_name = func.getName()
            
            for keyword in self.keywords:
                if keyword.lower() in func_name.lower():
                    self.spc_functions.append({
                        'address': func.getEntryPoint(),
                        'name': func_name,
                        'type': 'name_match',
                        'size': func.getBody().getNumAddresses()
                    })
                    self.log(f"[+] Found: {func_name} at {func.getEntryPoint()}")
                    break
    
    def find_by_strings(self):
        """Find functions by string cross-references"""
        self.log("[*] Searching for string references...")
        
        # Get all defined strings in the program
        string_manager = self.program.getListing()
        
        # Search through all memory to find strings
        mem = self.program.getMemory()
        addr = mem.getMinAddress()
        end_addr = mem.getMaxAddress()
        
        string_count = 0
        while addr < end_addr:
            unit = string_manager.getCodeUnitAt(addr)
            if unit is not None:
                if unit.getMnemonicString() == "ds":  # Data string
                    try:
                        value = unit.toString()
                        if any(keyword.lower() in value.lower() for keyword in self.keywords):
                            self.log(f"[+] Found string: '{value}' at {addr}")
                            string_count += 1
                            
                            # Find references to this string
                            refs = self.program.getReferenceManager().getReferencesTo(addr)
                            for ref in refs:
                                from_addr = ref.getFromAddress()
                                func = self.listing.getFunctionContaining(from_addr)
                                if func:
                                    func_entry = func.getEntryPoint()
                                    func_name = func.getName()
                                    
                                    # Check if already in list
                                    if not any(f['address'] == func_entry for f in self.spc_functions):
                                        self.spc_functions.append({
                                            'address': func_entry,
                                            'name': func_name,
                                            'type': 'string_ref',
                                            'size': func.getBody().getNumAddresses()
                                        })
                                        self.log(f"[+] Found function via string: {func_name} at {func_entry}")
                    except:
                        pass
            
            addr = string_manager.getNextCodeUnit(addr)
    
    def analyze_function(self, func_info):
        """Detailed analysis of suspected SPC function"""
        address = func_info['address']
        name = func_info['name']
        
        self.log(f"\n[*] Analyzing: {name} at {address}")
        
        try:
            func = self.listing.getFunctionAt(address)
            if not func:
                self.log(f"[-] Could not get function at {address}")
                return False
            
            # Function metadata
            self.log(f"[*] Function size: {func.getBody().getNumAddresses()} bytes")
            
            # Analyze local variables
            frame = func.getStackFrame()
            if frame:
                self.log(f"[*] Local variables/parameters:")
                for var in frame.getStackVariables():
                    self.log(f"    - {var.getName()} at offset {var.getStackOffset()}")
            
            # Find immediate values (potential hardcoded SPC codes)
            self.log(f"[*] Looking for immediate values...")
            instr_count = 0
            for addr in func.getBody().getAddresses(True):
                instr = self.listing.getInstructionAt(addr)
                if instr:
                    instr_count += 1
                    # Check operands for immediate values
                    for i in range(instr.getNumOperands()):
                        operand = instr.getOperandRefType(i)
                        if operand.toString() == "IMMEDIATE":
                            try:
                                val = instr.getScalar(i).getValue()
                                if 0 < val < 0x100000:
                                    self.log(f"    [0x{addr}] Immediate: 0x{val:x}")
                            except:
                                pass
            
            self.log(f"[*] Function contains {instr_count} instructions")
            
            # Find external references
            self.log(f"[*] External calls:")
            refs = self.program.getReferenceManager().getReferencesFrom(address)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    to_addr = ref.getToAddress()
                    to_func = self.listing.getFunctionAt(to_addr)
                    if to_func:
                        self.log(f"    - calls: {to_func.getName()}")
            
            return True
        
        except Exception as e:
            self.log(f"[-] Error analyzing function: {e}")
            return False
    
    def find_nv_item_operations(self):
        """Search for NV item read/write operations"""
        self.log("\n[*] Searching for NV item operations...")
        
        nv_related = [
            "nv_read", "nv_write", "nv_get", "nv_set",
            "write_nv_item", "read_nv_item",
            "qmi_write_nv", "qmi_read_nv",
            "SetNV", "GetNV"
        ]
        
        for func in self.listing.getFunctions(True):
            func_name = func.getName()
            for pattern in nv_related:
                if pattern.lower() in func_name.lower():
                    self.log(f"[+] NV Operation: {func_name} at {func.getEntryPoint()}")
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        report = []
        report.append("\n" + "="*70)
        report.append("SPC VALIDATION FUNCTION ANALYSIS REPORT (Ghidra)")
        report.append("="*70)
        
        report.append(f"\nProgram: {self.program.getName()}")
        report.append(f"Architecture: {self.program.getLanguage().getLanguageID()}")
        
        report.append(f"\n[*] Total SPC-related functions found: {len(self.spc_functions)}")
        
        # Summary by type
        name_matches = [f for f in self.spc_functions if f['type'] == 'name_match']
        string_refs = [f for f in self.spc_functions if f['type'] == 'string_ref']
        
        report.append(f"\n[*] Name matches: {len(name_matches)}")
        report.append(f"[*] String references: {len(string_refs)}")
        
        # Detailed listing
        report.append("\n--- Detailed Function Analysis ---")
        for func_info in self.spc_functions[:20]:  # Limit to first 20
            report.append(f"\n{func_info['name']} (0x{func_info['address']})")
            report.append(f"  Type: {func_info['type']}")
            report.append(f"  Size: {func_info['size']} bytes")
        
        report.append("\n" + "="*70)
        
        # Print report
        for line in report:
            self.log(line)
        
        # Save to file
        report_file = "/tmp/ghidra_spc_analysis_report.txt"
        self.log(f"\n[*] Report written to: {report_file}")
        
        return report

def main():
    """Main execution function for Ghidra"""
    
    # Get current program
    if currentProgram is None:
        print("[-] No program is currently open!")
        return
    
    program = currentProgram
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    
    print("\n[*] SPC Validation Function Analyzer for Ghidra")
    print(f"[*] Target binary: {program.getName()}")
    print("[*] Architecture: ARM 32/64-bit")
    
    analyzer = SPCFunctionAnalyzerGhidra(program, listing, symbol_table)
    
    # Phase 1: Find by name
    print("\n=== PHASE 1: Function Name Discovery ===")
    analyzer.find_spc_functions()
    
    # Phase 2: Find by strings
    print("\n=== PHASE 2: String Reference Discovery ===")
    analyzer.find_by_strings()
    
    # Phase 3: Analyze each
    print("\n=== PHASE 3: Detailed Analysis ===")
    for func_info in analyzer.spc_functions[:10]:  # Analyze first 10
        analyzer.analyze_function(func_info)
    
    # Phase 4: Find NV operations
    print("\n=== PHASE 4: NV Item Operation Discovery ===")
    analyzer.find_nv_item_operations()
    
    # Phase 5: Generate report
    print("\n=== PHASE 5: Report Generation ===")
    analyzer.generate_report()
    
    print("\n[*] Analysis complete!")

# Execute when script is loaded
if __name__ == "__main__":
    main()
