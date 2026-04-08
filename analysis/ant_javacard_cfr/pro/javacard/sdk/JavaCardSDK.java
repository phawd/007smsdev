/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.sdk;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import pro.javacard.sdk.SDKVersion;

public final class JavaCardSDK {
    private final Path path;
    private final SDKVersion version;
    private final Path exportDir;
    private final List<Path> apiJars;
    private final List<Path> toolJars;
    private final List<Path> compilerJars;

    public static Optional<JavaCardSDK> detectSDK(Path path) {
        if (path == null) {
            throw new NullPointerException("path is null");
        }
        SDKVersion version = JavaCardSDK.detectSDKVersion(path);
        if (version == null) {
            return Optional.empty();
        }
        Path exportDir = JavaCardSDK.getExportDir(version);
        List<Path> apiJars = JavaCardSDK.getApiJars(version);
        List<Path> compilerJars = JavaCardSDK.getCompilerJars(version);
        List<Path> toolJars = JavaCardSDK.getToolJars(version);
        JavaCardSDK sdk = new JavaCardSDK(path, version, exportDir, apiJars, toolJars, compilerJars);
        return Optional.of(sdk);
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    private static SDKVersion detectSDKVersion(Path root) {
        SDKVersion version = null;
        Path libDir = root.resolve("lib");
        Path tools = libDir.resolve("tools.jar");
        if (Files.exists(tools, new LinkOption[0])) {
            try (ZipFile apiZip = new ZipFile(tools.toFile());){
                String ver;
                ZipEntry toolsver = apiZip.getEntry("com/sun/javacard/toolsversion.properties");
                if (toolsver == null) return version;
                Properties verprop = new Properties();
                verprop.load(apiZip.getInputStream(toolsver));
                switch (ver = verprop.getProperty("converter.version")) {
                    case "3.0.3": {
                        SDKVersion sDKVersion = SDKVersion.V301;
                        return sDKVersion;
                    }
                    case "3.0.4": {
                        SDKVersion sDKVersion = SDKVersion.V304;
                        return sDKVersion;
                    }
                    case "3.0.5": {
                        SDKVersion sDKVersion = SDKVersion.V305;
                        return sDKVersion;
                    }
                    case "3.1.0": {
                        SDKVersion sDKVersion = SDKVersion.V310;
                        return sDKVersion;
                    }
                    case "3.2.0": {
                        SDKVersion sDKVersion = SDKVersion.V320;
                        return sDKVersion;
                    }
                    case "24.1": {
                        SDKVersion sDKVersion = SDKVersion.V320_24_1;
                        return sDKVersion;
                    }
                    case "25.0": {
                        SDKVersion sDKVersion = SDKVersion.V320_25_0;
                        return sDKVersion;
                    }
                }
                throw new IllegalStateException("Unknown SDK release: " + ver);
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        if (Files.exists(libDir.resolve("api21.jar"), new LinkOption[0])) {
            return SDKVersion.V212;
        }
        if (Files.exists(root.resolve("bin").resolve("api.jar"), new LinkOption[0])) {
            return SDKVersion.V211;
        }
        if (!Files.exists(libDir.resolve("converter.jar"), new LinkOption[0])) return version;
        version = SDKVersion.V221;
        Path api = libDir.resolve("api.jar");
        try (ZipFile apiZip = new ZipFile(api.toFile());){
            ZipEntry testEntry = apiZip.getEntry("javacardx/apdu/ExtendedLength.class");
            if (testEntry == null) return version;
            version = SDKVersion.V222;
            return version;
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private JavaCardSDK(Path root, SDKVersion version, Path exportDir, List<Path> apiJars, List<Path> toolJars, List<Path> compilerJars) {
        this.path = root;
        this.version = version;
        this.exportDir = this.path.resolve(exportDir);
        this.apiJars = apiJars.stream().map(this.path::resolve).collect(Collectors.toList());
        this.compilerJars = compilerJars.stream().map(this.path::resolve).collect(Collectors.toList());
        this.toolJars = toolJars.stream().map(this.path::resolve).collect(Collectors.toList());
    }

    public Path getRoot() {
        return this.path;
    }

    public SDKVersion getVersion() {
        return this.version;
    }

    public List<Path> getApiJars() {
        return Collections.unmodifiableList(this.apiJars);
    }

    public List<Path> getCompilerJars() {
        return Collections.unmodifiableList(this.compilerJars);
    }

    public List<Path> getToolJars() {
        return Collections.unmodifiableList(this.toolJars);
    }

    public Path getExportDir() {
        return this.exportDir;
    }

    public JavaCardSDK target(SDKVersion targetVersion) {
        if (this.version.targets.contains((Object)targetVersion)) {
            ArrayList<Path> apiJars = new ArrayList<Path>();
            apiJars.add(Paths.get("lib", "api_classic-" + targetVersion.v + ".jar"));
            apiJars.add(Paths.get("lib", "api_classic_annotations-" + targetVersion.v + ".jar"));
            Path exportPath = Paths.get("api_export_files_" + targetVersion.v, new String[0]);
            return new JavaCardSDK(this.path, targetVersion, exportPath, apiJars, this.toolJars, this.compilerJars);
        }
        throw new IllegalStateException("Can not target " + (Object)((Object)targetVersion) + " with " + (Object)((Object)this.version));
    }

    public ClassLoader getClassLoader() {
        return AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>(){

            @Override
            public URLClassLoader run() {
                try {
                    if (JavaCardSDK.this.version.equalOrNewer(SDKVersion.V301)) {
                        return new URLClassLoader(new URL[]{JavaCardSDK.this.path.resolve("lib").resolve("tools.jar").toUri().toURL()}, this.getClass().getClassLoader());
                    }
                    return new URLClassLoader(new URL[]{JavaCardSDK.this.path.resolve("lib").resolve("offcardverifier.jar").toUri().toURL()}, this.getClass().getClassLoader());
                }
                catch (MalformedURLException e) {
                    throw new RuntimeException("Could not load classes: " + e.getMessage());
                }
            }
        });
    }

    public String getRelease() {
        if (this.version == SDKVersion.V305) {
            try {
                Class<?> verifier = Class.forName("com.sun.javacard.offcardverifier.Verifier", false, this.getClassLoader());
                try {
                    verifier.getDeclaredMethod("verifyTargetPlatform", String.class);
                    return "3.0.5u3";
                }
                catch (NoSuchMethodException noSuchMethodException) {
                    try {
                        verifier.getDeclaredMethod("verifyCap", FileInputStream.class, String.class, Vector.class);
                        return "3.0.5u1";
                    }
                    catch (NoSuchMethodException noSuchMethodException2) {
                        return "3.0.5u2";
                    }
                }
            }
            catch (ReflectiveOperationException e) {
                throw new RuntimeException("Could not figure out SDK release: " + e.getMessage());
            }
        }
        return this.version.toString();
    }

    public static Path getExportDir(SDKVersion version) {
        switch (version) {
            case V212: {
                return Paths.get("api21_export_files", new String[0]);
            }
            case V310: 
            case V320: 
            case V320_24_1: 
            case V320_25_0: {
                return Paths.get("api_export_files_" + version.v, new String[0]);
            }
        }
        return Paths.get("api_export_files", new String[0]);
    }

    public static List<Path> getApiJars(SDKVersion version) {
        ArrayList<Path> jars = new ArrayList<Path>();
        switch (version) {
            case V211: {
                jars.add(Paths.get("bin", "api.jar"));
                break;
            }
            case V212: {
                jars.add(Paths.get("lib", "api21.jar"));
                break;
            }
            case V221: 
            case V222: {
                jars.add(Paths.get("lib", "api.jar"));
                break;
            }
            case V301: 
            case V304: 
            case V305: {
                jars.add(Paths.get("lib", "api_classic.jar"));
                break;
            }
            case V310: 
            case V320: 
            case V320_24_1: 
            case V320_25_0: {
                jars.add(Paths.get("lib", String.format("api_classic-%s.jar", version.v)));
                jars.add(Paths.get("lib", String.format("api_classic_annotations-%s.jar", version.v)));
                break;
            }
            default: {
                throw new IllegalStateException("Unknown SDK: " + (Object)((Object)version));
            }
        }
        if (version.isOneOf(SDKVersion.V304, SDKVersion.V305)) {
            jars.add(Paths.get("lib", "api_classic_annotations.jar"));
        }
        return jars;
    }

    public static List<Path> getToolJars(SDKVersion version) {
        ArrayList<Path> jars = new ArrayList<Path>();
        if (version.isOneOf(SDKVersion.V211)) {
            jars.add(Paths.get("bin", "converter.jar"));
        } else if (version.equalOrNewer(SDKVersion.V301)) {
            jars.add(Paths.get("lib", "tools.jar"));
        } else {
            jars.add(Paths.get("lib", "converter.jar"));
            jars.add(Paths.get("lib", "offcardverifier.jar"));
        }
        return jars;
    }

    public static List<Path> getCompilerJars(SDKVersion version) {
        ArrayList<Path> jars = new ArrayList<Path>();
        if (version.isOneOf(SDKVersion.V304, SDKVersion.V305)) {
            jars.add(Paths.get("lib", "tools.jar"));
            jars.add(Paths.get("lib", "api_classic_annotations.jar"));
        } else if (version.equalOrNewer(SDKVersion.V310)) {
            jars.add(Paths.get("lib", "tools.jar"));
            jars.add(Paths.get("lib", String.format("api_classic_annotations-%s.jar", version.v)));
        }
        return jars;
    }

    public boolean equals(Object o) {
        if (o instanceof JavaCardSDK) {
            JavaCardSDK other = (JavaCardSDK)o;
            return this.path.toAbsolutePath().equals(other.path.toAbsolutePath()) && this.version.equals((Object)other.version) && this.exportDir.equals(other.exportDir);
        }
        return false;
    }

    public int hashCode() {
        return Objects.hash(this.path, this.exportDir);
    }
}

