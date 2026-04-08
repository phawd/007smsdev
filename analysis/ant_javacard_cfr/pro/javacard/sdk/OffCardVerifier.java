/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.sdk;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import pro.javacard.capfile.CAPFile;
import pro.javacard.sdk.JavaCardSDK;
import pro.javacard.sdk.SDKVersion;
import pro.javacard.sdk.VerifierError;

public final class OffCardVerifier {
    private final JavaCardSDK sdk;

    public static OffCardVerifier withSDK(JavaCardSDK sdk) {
        if (sdk.getVersion().isOneOf(SDKVersion.V211, SDKVersion.V212)) {
            throw new RuntimeException("Verification is supported with JavaCard SDK 2.2.1 or later");
        }
        return new OffCardVerifier(sdk);
    }

    private OffCardVerifier(JavaCardSDK sdk) {
        this.sdk = sdk;
    }

    public void verifyAgainst(File f, JavaCardSDK target, Vector<File> exps) throws VerifierError, IOException {
        ArrayList<Path> exports = new ArrayList<Path>(exps.stream().map(File::toPath).collect(Collectors.toList()));
        exports.add(target.getExportDir());
        this.verify(f.toPath(), exports);
    }

    public void verifyAgainst(Path f, JavaCardSDK target, List<Path> exps) throws VerifierError, IOException {
        if (target.getVersion().isOneOf(SDKVersion.V304, SDKVersion.V305, SDKVersion.V310) && this.sdk.getVersion() != SDKVersion.V320_25_0) {
            System.err.println("NB! Please use JavaCard SDK 3.2.0 / 25.0 for verifying!");
        } else if (!this.sdk.getRelease().equals("3.0.5u4")) {
            System.err.println("NB! Please use JavaCard SDK 3.0.5u4 or later for verifying!");
        }
        ArrayList<Path> exports = new ArrayList<Path>(exps.stream().collect(Collectors.toList()));
        exports.add(target.getExportDir());
        this.verify(f, exports);
    }

    public void verify(Path f, List<Path> exps) throws VerifierError, IOException {
        Path tmp = Files.createTempDirectory("capfile", new FileAttribute[0]);
        try (InputStream in = Files.newInputStream(f, new OpenOption[0]);){
            CAPFile cap = CAPFile.fromStream(in);
            Class<?> verifier = Class.forName("com.sun.javacard.offcardverifier.Verifier", true, this.sdk.getClassLoader());
            Vector<File> expfiles = new Vector<File>();
            for (Path e : exps) {
                if (Files.isDirectory(e, new LinkOption[0])) {
                    expfiles.addAll(Files.walk(e.toRealPath(new LinkOption[0]), new FileVisitOption[0]).filter(p -> p.toString().endsWith(".exp")).map(Path::toFile).collect(Collectors.toList()));
                    continue;
                }
                if (!Files.isReadable(e)) continue;
                if (e.toString().endsWith(".exp")) {
                    expfiles.add(e.toFile());
                    continue;
                }
                if (!e.toString().endsWith(".jar")) continue;
                expfiles.addAll(OffCardVerifier.extractExps(e, tmp).stream().map(Path::toFile).collect(Collectors.toList()));
            }
            String packagename = cap.getPackageName();
            try (FileInputStream input = new FileInputStream(f.toFile());){
                if (this.sdk.getRelease().equals("3.0.5u3") || this.sdk.getRelease().equals("3.0.5u2") || this.sdk.getVersion().equalOrNewer(SDKVersion.V310)) {
                    Method m = verifier.getMethod("verifyCap", File.class, String.class, Vector.class);
                    m.invoke(null, f.toFile(), packagename, expfiles);
                } else {
                    Method m = verifier.getMethod("verifyCap", FileInputStream.class, String.class, Vector.class);
                    m.invoke(null, input, packagename, expfiles);
                }
            }
            catch (InvocationTargetException e) {
                throw new VerifierError(e.getTargetException().getMessage(), e.getTargetException());
            }
            catch (Exception e) {
                throw new VerifierError("Verification failed: " + e.getMessage(), e);
            }
        }
        catch (IOException | ReflectiveOperationException e) {
            throw new RuntimeException("Could not run verifier: " + e.getMessage(), e);
        }
        finally {
            OffCardVerifier.rmminusrf(tmp);
        }
    }

    private static void rmminusrf(Path path) {
        try {
            Files.walk(path, new FileVisitOption[0]).sorted(Comparator.reverseOrder()).forEach(CAPFile::uncheckedDelete);
        }
        catch (FileNotFoundException | NoSuchFileException iOException) {
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Path under(Path out, String name) {
        Path p = out.resolve(name).normalize().toAbsolutePath();
        if (!p.startsWith(out)) {
            throw new IllegalArgumentException("Invalid path in JAR: " + p + " vs " + out);
        }
        return p;
    }

    public static List<Path> extractExps(Path jarfilePath, Path out) throws IOException {
        ArrayList<Path> exps = new ArrayList<Path>();
        try (JarFile jarfile = new JarFile(jarfilePath.toFile());){
            Enumeration<JarEntry> entries = jarfile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().toLowerCase().endsWith(".exp")) continue;
                Path f = OffCardVerifier.under(out, entry.getName());
                Path dir = f.getParent();
                if (dir == null) {
                    throw new IOException("Null parent");
                }
                if (!Files.isDirectory(dir, new LinkOption[0])) {
                    Files.createDirectories(dir, new FileAttribute[0]);
                }
                try (InputStream is = jarfile.getInputStream(entry);
                     OutputStream fo = Files.newOutputStream(f, new OpenOption[0]);){
                    int r;
                    byte[] buf = new byte[1024];
                    while ((r = is.read(buf)) != -1) {
                        fo.write(buf, 0, r);
                    }
                }
                exps.add(f);
            }
        }
        return exps;
    }
}

