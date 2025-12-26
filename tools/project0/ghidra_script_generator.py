#!/usr/bin/env python3
"""
Generate a Ghidra Java script for headless analysis (based on FindNCKUnlockLogic.java)
Writes to `analysis/ghidra_scripts/generated_FindNCKUnlockLogic.java`.
User should run `analyzeHeadless` with the generated script.
"""
import os

TEMPLATE = '''// Generated from template: FindNCKUnlockLogic
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class generated_FindNCKUnlockLogic extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("[Ghidra] Searching for NCK/unlock logic...");
        Program program = getCurrentProgram();
        int found = 0;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName().toLowerCase();
            if (name.contains("unlock") || name.contains("nck") || name.contains("carrier_lock")) {
                found++;
                println("\n=== Function: " + func.getName() + " ===");
                try {
                    String decomp = decompileFunction(func, 60, monitor);
                    println(decomp);
                } catch (Exception e) {
                    println("[Error decompiling] " + func.getName());
                }
            }
        }
        if (found == 0) {
            println("[Ghidra] No functions with 'unlock', 'nck', or 'carrier_lock' found.");
        }
    }

    private String decompileFunction(Function func, int timeout, TaskMonitor monitor) throws Exception {
        ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
        decomp.openProgram(func.getProgram());
        decomp.setSimplificationStyle("decompile");
        ghidra.app.decompiler.DecompileResults res = decomp.decompileFunction(func, timeout, monitor);
        if (res.decompileCompleted()) {
            return res.getDecompiledFunction().getC();
        } else {
            return "[Decompilation failed]";
        }
    }
}
'''

OUT = os.path.join(os.getcwd(), 'analysis', 'ghidra_scripts',
                   'generated_FindNCKUnlockLogic.java')
if __name__ == '__main__':
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as f:
        f.write(TEMPLATE)
    print('Wrote', OUT)
