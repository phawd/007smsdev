/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.tools.ant.Task
 */
package pro.javacard.ant;

import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.stream.IntStream;
import org.apache.tools.ant.Task;
import pro.javacard.ant.JCCap;
import pro.javacard.ant.Misc;

public final class JavaCard
extends Task {
    private final int[] lts = new int[]{8, 11, 17, 21};
    private String master_jckit_path = null;
    private Vector<JCCap> packages = new Vector();

    public void setJCKit(String msg) {
        this.master_jckit_path = msg;
    }

    public JCCap createCap() {
        JCCap pkg = new JCCap(this.master_jckit_path);
        this.packages.add(pkg);
        return pkg;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void execute() {
        Logger rootLogger = LogManager.getLogManager().getLogger("");
        Level beforeLevel = rootLogger.getLevel();
        Thread cleanup = new Thread(() -> {
            this.log("Ctrl-C, cleaning up", 2);
            Misc.cleanTemp();
        });
        Runtime.getRuntime().addShutdownHook(cleanup);
        String ver = JavaCard.class.getPackage().getImplementationVersion();
        this.log("ant-javacard " + (ver == null ? "development" : ver), 2);
        if (IntStream.of(this.lts).noneMatch(x -> x == Misc.getCurrentJDKVersion())) {
            this.log("Please consider using a LTS JDK version: " + Arrays.toString(this.lts), 1);
        }
        try {
            for (JCCap p : this.packages) {
                p.execute();
            }
        }
        finally {
            Runtime.getRuntime().removeShutdownHook(cleanup);
            rootLogger.setLevel(beforeLevel);
        }
    }
}

