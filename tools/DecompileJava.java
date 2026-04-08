// Ghidra Java Script
// Decompiles Java classes and prints source code
// Can be used in headless mode with -postScript

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.PrintWriter;

public class DecompileJava extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = getCurrentProgram();
        String programName = program.getName();
        println("=== Decompiling: " + programName + " ===");

        DecompInterface decomp = new DecompInterface();
        if (!decomp.openProgram(program)) {
            println("Decompiler initialisation failed for " + programName);
            return;
        }

        FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
        for (Function func : funcs) {
            // Decompile each function
            DecompileResults results = decomp.decompileFunction(func, 60, monitor);
            if (results.decompileCompleted()) {
                String cCode = results.getDecompiledFunction().getC();
                println("// Function: " + func.getName());
                println(cCode);
            } else {
                println("// Decompilation failed for: " + func.getName());
            }
        }
        
        decomp.dispose();
        println("=== Finished: " + programName + " ===\n");
    }
}
