// Ghidra analysis script - export functions and decompile
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

DecompInterface decomp = new DecompInterface();
decomp.openProgram(currentProgram);

String programName = currentProgram.getName();
String reportsDir = "F:/repo/zerosms/analysis/critical_binaries_analysis/reports_additional/";
String decompiledDir = "F:/repo/zerosms/analysis/critical_binaries_analysis/decompiled_additional/";

// Export function list
PrintWriter fw = new PrintWriter(new FileWriter(reportsDir + programName + "_functions.txt"));
fw.println("=== FUNCTION ANALYSIS: " + programName + " ===\n");

int totalFuncs = 0;
int interestingFuncs = 0;

FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
while (funcs.hasNext()) {
    Function f = funcs.next();
    totalFuncs++;
    String name = f.getName();
    String addr = f.getEntryPoint().toString();
    
    // Flag interesting functions
    String flag = "";
    if (name.toLowerCase().contains("unlock") || name.toLowerCase().contains("carrier") ||
        name.toLowerCase().contains("perso") || name.toLowerCase().contains("nv") ||
        name.toLowerCase().contains("simlock") || name.toLowerCase().contains("verify") ||
        name.toLowerCase().contains("qmi") || name.toLowerCase().contains("diag")) {
        flag = " <<< INTERESTING";
        interestingFuncs++;
    }
    
    fw.println(addr + " | " + name + flag);
}

fw.println("\n=== SUMMARY ===");
fw.println("Total functions: " + totalFuncs);
fw.println("Interesting functions: " + interestingFuncs);
fw.close();

// Decompile interesting functions
PrintWriter dw = new PrintWriter(new FileWriter(decompiledDir + programName + "_decompiled.c"));
dw.println("/* Decompiled code for: " + programName + " */\n");

funcs = currentProgram.getFunctionManager().getFunctions(true);
while (funcs.hasNext()) {
    Function f = funcs.next();
    String name = f.getName();
    
    if (name.toLowerCase().contains("unlock") || name.toLowerCase().contains("carrier") ||
        name.toLowerCase().contains("perso") || name.toLowerCase().contains("nv") ||
        name.toLowerCase().contains("simlock") || name.toLowerCase().contains("verify") ||
        name.toLowerCase().contains("qmi") || name.toLowerCase().contains("diag") ||
        name.toLowerCase().contains("modem") || name.toLowerCase().contains("at_")) {
        
        DecompileResults results = decomp.decompileFunction(f, 60, null);
        if (results.decompileCompleted()) {
            dw.println("// Function: " + name + " @ " + f.getEntryPoint());
            dw.println(results.getDecompiledFunction().getC());
            dw.println("\n" + "=".repeat(80) + "\n");
        }
    }
}

dw.close();
decomp.dispose();
printf("Analysis complete for %s - %d total functions, %d interesting\n", programName, totalFuncs, interestingFuncs);
