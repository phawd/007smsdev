/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.ant;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Vector;
import java.util.stream.Collectors;
import pro.javacard.ant.Misc;
import pro.javacard.capfile.CAPFile;
import pro.javacard.sdk.ExportFileHelper;
import pro.javacard.sdk.JavaCardSDK;
import pro.javacard.sdk.OffCardVerifier;
import pro.javacard.sdk.VerifierError;

public final class DummyMain {
    private static final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    static int runcycle(String[] argv) throws IOException {
        String capfile;
        Path targetsdkpath;
        Vector<String> args = new Vector<String>(Arrays.asList(argv));
        if (args.isEmpty()) {
            ProtectionDomain pd = DummyMain.class.getProtectionDomain();
            System.out.println("This is an ANT task (ant-javacard " + DummyMain.class.getPackage().getImplementationVersion() + ")");
            System.out.println("Read usage instructions from https://github.com/martinpaljak/ant-javacard#syntax");
            if (pd != null && pd.getCodeSource() != null && pd.getCodeSource().getLocation() != null) {
                try {
                    System.out.println();
                    String f = pd.getCodeSource().getLocation().getPath();
                    Path p = Paths.get(f, new String[0]);
                    byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p));
                    System.out.println("SHA256 (" + f + ") = " + DummyMain.bin2hex(sha256));
                }
                catch (Exception e) {
                    System.out.println("Could not verify integrity: " + e.getMessage());
                }
            }
            System.out.println();
            System.out.println("But you can use it to dump/verify CAP files, like this:");
            System.out.println("$ java -jar ant-javacard.jar <capfile>");
            return 1;
        }
        if (args.size() == 1) {
            String capfile2 = args.remove(0);
            Path path = Paths.get(capfile2, new String[0]);
            if (Files.isRegularFile(path, new LinkOption[0]) && capfile2.endsWith(".cap")) {
                try {
                    CAPFile cap = CAPFile.fromBytes(Files.readAllBytes(path));
                    cap.dump(System.out);
                    return 0;
                }
                catch (Exception e) {
                    System.err.printf("Failed to read/parse CAP file: %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
                    return 1;
                }
            }
            if (Files.isRegularFile(path, new LinkOption[0]) && capfile2.endsWith(".exp")) {
                try {
                    System.out.printf("%s: %s%n", new Object[]{path, ExportFileHelper.getVersion(path).get()});
                    return 0;
                }
                catch (Exception e) {
                    System.err.printf("Failed to read/parse EXP file: %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
                    return 1;
                }
            }
            System.err.println("Usage: java -jar ant-javacard.jar <capfile|expfile>");
            return 1;
        }
        Path sdkpath = Paths.get(args.remove(0), new String[0]);
        String next = args.remove(0);
        if (Files.isDirectory(Paths.get(next, new String[0]), new LinkOption[0])) {
            targetsdkpath = Paths.get(next, new String[0]);
            capfile = args.remove(0);
        } else {
            capfile = next;
            targetsdkpath = sdkpath;
        }
        Vector exps = args.stream().map(File::new).collect(Collectors.toCollection(Vector::new));
        CAPFile cap = CAPFile.fromBytes(Files.readAllBytes(Paths.get(capfile, new String[0])));
        try {
            JavaCardSDK sdk = JavaCardSDK.detectSDK(sdkpath).orElseThrow(() -> new VerifierError("No SDK detected in " + sdkpath));
            JavaCardSDK target = JavaCardSDK.detectSDK(targetsdkpath).orElseThrow(() -> new VerifierError("No target SDK detected with " + targetsdkpath));
            OffCardVerifier verifier = OffCardVerifier.withSDK(sdk);
            cap.dump(System.out);
            verifier.verifyAgainst(new File(capfile), target, exps);
            System.out.printf("Verified %s with SDK v%s against SDK v%s%n", new Object[]{capfile, sdk.getVersion(), target.getVersion()});
            return 0;
        }
        catch (VerifierError e) {
            System.err.println("Verification failed: " + e.getMessage());
            return 1;
        }
    }

    public static void main(String[] argv) {
        try {
            DummyMain.runcycle(argv);
        }
        catch (Throwable e) {
            Misc.cleanTemp();
            System.err.printf("Error: %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
            if (System.getenv("ANT_JAVACARD_DEBUG") != null) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }

    static String bin2hex(byte[] data) {
        int l = data.length;
        char[] out = new char[l << 1];
        int j = 0;
        for (int i = 0; i < l; ++i) {
            out[j++] = HEX[(0xF0 & data[i]) >>> 4];
            out[j++] = HEX[0xF & data[i]];
        }
        return new String(out);
    }
}

