/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.tools.ant.BuildException
 *  org.apache.tools.ant.Project
 *  org.apache.tools.ant.Task
 *  org.apache.tools.ant.taskdefs.Jar
 *  org.apache.tools.ant.taskdefs.Java
 *  org.apache.tools.ant.taskdefs.Javac
 *  org.apache.tools.ant.types.Environment$Variable
 *  org.apache.tools.ant.types.FileSet
 *  org.apache.tools.ant.types.Path
 *  org.apache.tools.ant.types.ResourceCollection
 */
package pro.javacard.ant;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.taskdefs.Jar;
import org.apache.tools.ant.taskdefs.Java;
import org.apache.tools.ant.taskdefs.Javac;
import org.apache.tools.ant.types.Environment;
import org.apache.tools.ant.types.FileSet;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.ResourceCollection;
import pro.javacard.ant.HelpingBuildException;
import pro.javacard.ant.JCApplet;
import pro.javacard.ant.JCImport;
import pro.javacard.ant.Misc;
import pro.javacard.capfile.CAPFile;
import pro.javacard.sdk.JavaCardSDK;
import pro.javacard.sdk.OffCardVerifier;
import pro.javacard.sdk.SDKVersion;
import pro.javacard.sdk.VerifierError;

public class JCCap
extends Task {
    static final String DEFAULT_CAP_NAME_TEMPLATE = "%n_%a_%h_%j_%J.cap";
    static final String DEFAULT_CAP_NAME_TEMPLATE_LIB = "%n_%a_%v_%h.cap";
    private final String master_jckit_path;
    private JavaCardSDK jckit = null;
    private String classes_path = null;
    private String sources_path = null;
    private String sources2_path = null;
    private String includes = null;
    private String excludes = null;
    private String package_name = null;
    private byte[] package_aid = null;
    private String package_version = null;
    private List<JCApplet> raw_applets = new ArrayList<JCApplet>();
    private List<JCImport> raw_imports = new ArrayList<JCImport>();
    private String output_cap = null;
    private String output_exp = null;
    private String output_jar = null;
    private String output_jca = null;
    private String jckit_path = null;
    private JavaCardSDK targetsdk = null;
    private String raw_targetsdk = null;
    private boolean verify = true;
    private boolean debug = false;
    private boolean strip = false;
    private boolean ints = false;
    private boolean exportmap = false;
    static final String _logconf;
    static final boolean loghack;

    public JCCap(String master_jckit_path) {
        this.master_jckit_path = master_jckit_path;
    }

    public void setJCKit(String msg) {
        this.jckit_path = msg;
    }

    public void setOutput(String msg) {
        this.output_cap = msg;
    }

    public void setExport(String msg) {
        this.output_exp = msg;
    }

    public void setJar(String msg) {
        this.output_jar = msg;
    }

    public void setJca(String msg) {
        this.output_jca = msg;
    }

    public void setPackage(String msg) {
        this.package_name = msg;
    }

    public void setClasses(String msg) {
        this.classes_path = msg;
    }

    public void setVersion(String msg) {
        this.package_version = msg;
    }

    public void setSources(String arg) {
        this.sources_path = arg;
    }

    public void setSources2(String arg) {
        this.sources2_path = arg;
    }

    public void setIncludes(String arg) {
        this.includes = arg;
    }

    public void setExcludes(String arg) {
        this.excludes = arg;
    }

    public void setVerify(boolean arg) {
        this.verify = arg;
    }

    public void setDebug(boolean arg) {
        this.debug = arg;
    }

    public void setStrip(boolean arg) {
        this.strip = arg;
    }

    public void setInts(boolean arg) {
        this.ints = arg;
    }

    public void setExportmap(boolean arg) {
        this.exportmap = arg;
    }

    public void setTargetsdk(String arg) {
        this.raw_targetsdk = arg;
    }

    public void setAID(String msg) {
        try {
            this.package_aid = Misc.stringToBin(msg);
            if (this.package_aid.length < 5 || this.package_aid.length > 16) {
                throw new BuildException("Package AID must be between 5 and 16 bytes: " + Misc.encodeHexString(this.package_aid) + " (" + this.package_aid.length + ")");
            }
        }
        catch (IllegalArgumentException e) {
            throw new BuildException("Not a correct package AID: " + e.getMessage());
        }
    }

    public JCApplet createApplet() {
        JCApplet applet = new JCApplet();
        this.raw_applets.add(applet);
        return applet;
    }

    public JCImport createImport() {
        JCImport imp = new JCImport();
        this.raw_imports.add(imp);
        return imp;
    }

    public JCImport createJimport() {
        return this.createImport();
    }

    private Optional<JavaCardSDK> findSDK() {
        if (this.jckit_path != null) {
            return JavaCardSDK.detectSDK(this.getProject().resolveFile(this.jckit_path).toPath());
        }
        if (this.master_jckit_path != null) {
            return JavaCardSDK.detectSDK(this.getProject().resolveFile(this.master_jckit_path).toPath());
        }
        String propPath = this.getProject().getProperty("jc.home");
        if (propPath != null) {
            return JavaCardSDK.detectSDK(this.getProject().resolveFile(propPath).toPath());
        }
        String envPath = System.getenv("JC_HOME");
        if (envPath != null) {
            return JavaCardSDK.detectSDK(this.getProject().resolveFile(envPath).toPath());
        }
        return Optional.empty();
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    private void check() {
        this.jckit = this.findSDK().orElseThrow(() -> new HelpingBuildException("No usable JavaCard SDK referenced"));
        this.log("INFO: using JavaCard " + (Object)((Object)this.jckit.getVersion()) + " SDK in " + this.jckit.getRoot() + " with JDK " + Misc.getCurrentJDKVersion(), 2);
        if (this.raw_targetsdk != null) {
            Optional<SDKVersion> targetVersion = SDKVersion.fromVersion(this.raw_targetsdk);
            if (targetVersion.isPresent() && !this.jckit.getVersion().targets().isEmpty()) {
                SDKVersion sDKVersion = targetVersion.get();
                if (this.jckit.getVersion().equals((Object)sDKVersion)) {
                    this.log("WARN: \"targetsdk\" ignored as it matches \"jckit\" version", 1);
                } else {
                    if (!this.jckit.getVersion().targets().contains((Object)sDKVersion)) throw new HelpingBuildException("Can not target JavaCard " + (Object)((Object)sDKVersion) + " with JavaCard kit " + (Object)((Object)this.jckit.getVersion()));
                    this.targetsdk = this.jckit.target(sDKVersion);
                }
            } else {
                this.targetsdk = JavaCardSDK.detectSDK(this.getProject().resolveFile(this.raw_targetsdk).toPath()).orElseThrow(() -> new HelpingBuildException("Invalid \"targetsdk\": " + this.raw_targetsdk));
                if (!this.jckit.getVersion().targets().isEmpty() && !this.targetsdk.getVersion().equalOrNewer(SDKVersion.V304)) {
                    throw new HelpingBuildException("targetsdk " + (Object)((Object)this.targetsdk.getVersion()) + " is not compatible with jckit " + (Object)((Object)this.jckit.getVersion()));
                }
            }
        }
        if (this.targetsdk == null) {
            this.targetsdk = this.jckit;
        } else if (this.jckit.getRoot() != this.targetsdk.getRoot()) {
            this.log("INFO: targeting JavaCard " + (Object)((Object)this.targetsdk.getVersion()) + " SDK in " + this.targetsdk.getRoot(), 2);
        } else {
            this.log("INFO: targeting JavaCard " + (Object)((Object)this.targetsdk.getVersion()), 2);
        }
        if (this.sources_path != null && this.sources2_path != null) {
            this.log("WARN: sources2 is deprecated in favor of multiple paths in sources", 1);
        }
        if (this.sources_path == null && this.classes_path == null) {
            if (this.getProject().resolveFile("src/main/javacard").isDirectory()) {
                this.sources_path = "src/main/javacard";
            } else if (this.getProject().resolveFile("src/main/java").isDirectory()) {
                this.sources_path = "src/main/java";
            }
        }
        if (this.sources_path == null && this.classes_path == null) {
            throw new HelpingBuildException("Must specify \"sources\" or \"classes\"");
        }
        if (this.package_version == null) {
            this.package_version = "0.0";
        } else {
            if (!this.package_version.matches("^[0-9]{1,3}\\.[0-9]{1,3}$")) {
                throw new HelpingBuildException("Invalid package version: " + this.package_version);
            }
            if (Arrays.stream(this.package_version.split("\\.")).map(e -> Integer.parseInt(e, 10)).anyMatch(e -> e < 0 || e > 127)) {
                throw new HelpingBuildException("Illegal package version value: " + this.package_version);
            }
        }
        for (JCImport jCImport : this.raw_imports) {
            if (jCImport.jar != null && !this.getProject().resolveFile(jCImport.jar).isFile()) {
                throw new BuildException("Import JAR does not exist: " + jCImport.jar);
            }
            if (jCImport.exps == null || this.getProject().resolveFile(jCImport.exps).isDirectory()) continue;
            throw new BuildException("Import EXP files folder does not exist: " + jCImport.exps);
        }
        int applet_counter = 0;
        for (JCApplet a : this.raw_applets) {
            ++applet_counter;
            if (a.klass == null) {
                throw new HelpingBuildException("Applet class is missing");
            }
            if (this.package_name != null) {
                if (!a.klass.contains(".")) {
                    a.klass = this.package_name + "." + a.klass;
                } else if (!a.klass.startsWith(this.package_name)) {
                    throw new HelpingBuildException("Applet class " + a.klass + " is not in package " + this.package_name);
                }
            } else {
                if (!a.klass.contains(".")) throw new HelpingBuildException("Applet must be in a package!");
                String pkgname = a.klass.substring(0, a.klass.lastIndexOf("."));
                this.log("INFO: setting package name to " + pkgname, 2);
                this.package_name = pkgname;
            }
            if (this.package_aid != null) {
                if (a.aid != null) {
                    if (Arrays.equals(Arrays.copyOf(this.package_aid, 5), Arrays.copyOf(a.aid, 5))) continue;
                    throw new HelpingBuildException("Package RID does not match Applet RID");
                }
                a.aid = Arrays.copyOf(this.package_aid, this.package_aid.length + 1);
                a.aid[this.package_aid.length] = (byte)applet_counter;
                this.log("INFO: generated applet AID: " + Misc.encodeHexString(a.aid) + " for " + a.klass, 2);
                continue;
            }
            if (a.aid == null) throw new HelpingBuildException("Both package AID and applet AID are missing!");
            this.package_aid = Arrays.copyOf(a.aid, 5);
        }
        if (this.package_aid == null) {
            throw new HelpingBuildException("Must specify package AID");
        }
        if (this.raw_applets.isEmpty()) {
            if (this.package_name == null) {
                throw new HelpingBuildException("Must specify package name if no applets");
            }
            this.log("Building library from package " + this.package_name + " (AID: " + Misc.encodeHexString(this.package_aid) + ")", 2);
        } else {
            this.log("Building CAP with " + applet_counter + " applet" + (applet_counter > 1 ? "s" : "") + " from package " + this.package_name + " (AID: " + Misc.encodeHexString(this.package_aid) + ")", 2);
            for (JCApplet app : this.raw_applets) {
                this.log(app.klass + " " + Misc.encodeHexString(app.aid), 2);
            }
        }
        if (this.output_exp != null) {
            String string = Misc.lastName(this.package_name);
            this.output_jar = new File(this.output_exp, string + ".jar").toString();
        }
        if (this.output_cap != null) return;
        this.output_cap = this.raw_applets.size() == 0 ? DEFAULT_CAP_NAME_TEMPLATE_LIB : DEFAULT_CAP_NAME_TEMPLATE;
    }

    private Path mkPath(String name) {
        if (name == null) {
            return new Path(this.getProject());
        }
        return new Path(this.getProject(), name);
    }

    private void compile() {
        java.nio.file.Path tmp;
        String[] sources_paths;
        Project project = this.getProject();
        this.setTaskName("compile");
        Javac j = new Javac();
        j.setProject(project);
        j.setEncoding("utf-8");
        j.setTaskName("compile");
        Path sources = this.mkPath(null);
        String pattern = Pattern.quote(File.pathSeparator);
        for (String path : sources_paths = this.sources_path.split(pattern)) {
            sources.append(this.mkPath(path));
        }
        if (this.sources2_path != null) {
            sources.append(this.mkPath(this.sources2_path));
        }
        j.setSrcdir(sources);
        if (this.includes != null) {
            j.setIncludes(this.includes);
        }
        if (this.excludes != null) {
            j.setExcludes(this.excludes);
        }
        j.setSourcepath(new Path(project, null));
        this.log("Compiling files from " + sources, 2);
        if (this.classes_path != null) {
            tmp = project.resolveFile(this.classes_path).toPath();
            if (!Files.exists(tmp, new LinkOption[0])) {
                try {
                    Files.createDirectories(tmp, new FileAttribute[0]);
                }
                catch (IOException e) {
                    throw new BuildException("Could not create classes folder " + tmp.toAbsolutePath());
                }
            }
        } else {
            tmp = Misc.makeTemp("classes-" + this.runIdentifier());
            this.classes_path = tmp.toAbsolutePath().toString();
        }
        j.setDestdir(tmp.toFile());
        j.setDebug(true);
        j.setDebugLevel("lines,vars,source");
        String javaVersion = this.jckit.getVersion().javaVersion();
        int jdkver = Misc.getCurrentJDKVersion();
        if (!this.jckit.getVersion().jdkVersions().contains(jdkver)) {
            if (jdkver > 17 && !this.jckit.getVersion().isOneOf(SDKVersion.V320_25_0)) {
                throw new HelpingBuildException("JDK 17 is the latest supported JDK.");
            }
            if (this.jckit.getVersion().isOneOf(SDKVersion.V211, SDKVersion.V212, SDKVersion.V221, SDKVersion.V222) && jdkver > 8) {
                throw new HelpingBuildException("Use JDK 8 with JavaCard kit v2.x");
            }
            if (jdkver > 11 && !this.jckit.getVersion().isOneOf(SDKVersion.V310, SDKVersion.V320, SDKVersion.V320_24_1, SDKVersion.V320_25_0)) {
                throw new HelpingBuildException(String.format("Can't use JDK %d with JavaCard kit %s (use JDK 11)", new Object[]{jdkver, this.jckit.getVersion()}));
            }
            if (jdkver == 8 && this.jckit.getVersion().isOneOf(SDKVersion.V320)) {
                throw new HelpingBuildException(String.format("Should not use JDK %d with JavaCard kit %s (use JDK 11 or 17)", new Object[]{jdkver, this.jckit.getVersion()}));
            }
        }
        j.setTarget(javaVersion);
        j.setSource(javaVersion);
        j.setIncludeantruntime(false);
        j.createCompilerArg().setValue("-Xlint");
        j.createCompilerArg().setValue("-Xlint:-options");
        j.createCompilerArg().setValue("-Xlint:-serial");
        if (this.jckit.getVersion().isOneOf(SDKVersion.V304, SDKVersion.V305, SDKVersion.V310)) {
            j.createCompilerArg().setLine("-processor com.oracle.javacard.stringproc.StringConstantsProcessor");
            Path pcp = new Javac().createClasspath();
            for (java.nio.file.Path jar : this.jckit.getCompilerJars()) {
                pcp.append(this.mkPath(jar.toString()));
            }
            j.createCompilerArg().setLine("-processorpath \"" + pcp.toString() + "\"");
            j.createCompilerArg().setValue("-Xlint:all,-processing");
        }
        j.setFailonerror(true);
        j.setFork(true);
        j.setListfiles(true);
        Path cp = j.createClasspath();
        JavaCardSDK sdk = this.targetsdk == null ? this.jckit : this.targetsdk;
        for (java.nio.file.Path jar : sdk.getApiJars()) {
            cp.append(this.mkPath(jar.toString()));
        }
        for (JCImport i : this.raw_imports) {
            if (i.jar == null) continue;
            cp.append(this.mkPath(i.jar));
        }
        j.execute();
    }

    private void addKitClasses(Java j) {
        Path cp = j.createClasspath();
        for (java.nio.file.Path jar : this.jckit.getToolJars()) {
            cp.append(this.mkPath(jar.toString()));
        }
        j.setClasspath(cp);
    }

    private void convert(java.nio.file.Path applet_folder, Set<java.nio.file.Path> exps) {
        this.setTaskName("convert");
        Java j = new Java((Task)this);
        j.setTaskName("convert");
        j.setFailonerror(true);
        j.setFork(true);
        this.addKitClasses(j);
        if (this.jckit.getVersion().equalOrNewer(SDKVersion.V301)) {
            j.setClassname("com.sun.javacard.converter.Main");
            if (loghack) {
                Environment.Variable jclog = new Environment.Variable();
                jclog.setKey("java.util.logging.config.file");
                jclog.setValue(_logconf);
                j.addSysproperty(jclog);
            }
        } else {
            j.setClassname("com.sun.javacard.converter.Converter");
        }
        j.createArg().setLine("-d '" + applet_folder + "'");
        j.createArg().setLine("-classdir '" + this.classes_path + "'");
        StringJoiner expstringbuilder = new StringJoiner(File.pathSeparator);
        if (this.jckit.getVersion().targets().contains((Object)this.targetsdk.getVersion())) {
            j.createArg().setLine("-target " + this.targetsdk.getVersion().toString());
        } else {
            expstringbuilder.add(this.targetsdk.getExportDir().toString());
        }
        for (java.nio.file.Path imp : exps) {
            expstringbuilder.add(imp.toString());
        }
        if (expstringbuilder.length() > 0) {
            j.createArg().setLine("-exportpath '" + expstringbuilder + "'");
        }
        j.createArg().setLine("-verbose");
        j.createArg().setLine("-nobanner");
        if (this.debug) {
            j.createArg().setLine("-debug");
        }
        if (!this.verify && !this.jckit.getVersion().isOneOf(SDKVersion.V211, SDKVersion.V212)) {
            j.createArg().setLine("-noverify");
        }
        if (this.jckit.getVersion().equalOrNewer(SDKVersion.V301)) {
            j.createArg().setLine("-useproxyclass");
        }
        if (this.ints) {
            j.createArg().setLine("-i");
        }
        if (this.exportmap) {
            j.createArg().setLine("-exportmap");
        }
        String outputs = "CAP";
        if (this.output_exp != null || this.raw_applets.size() > 0 && this.verify) {
            outputs = outputs + " EXP";
        }
        if (this.output_jca != null) {
            outputs = outputs + " JCA";
        }
        j.createArg().setLine("-out " + outputs);
        for (JCApplet app : this.raw_applets) {
            j.createArg().setLine("-applet " + Misc.hexAID(app.aid) + " " + app.klass);
        }
        j.createArg().setLine(this.package_name + " " + Misc.hexAID(this.package_aid) + " " + this.package_version);
        this.log("command: " + j.getCommandLine(), 4);
        j.execute();
    }

    private int runIdentifier() {
        return Objects.hashCode((Object)this);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void execute() {
        Project project = this.getProject();
        this.setTaskName("javacard");
        this.check();
        try {
            if (this.sources_path != null) {
                this.compile();
            }
            java.nio.file.Path applet_folder = Misc.makeTemp("applet-" + this.runIdentifier());
            TreeSet<java.nio.file.Path> exps = new TreeSet<java.nio.file.Path>();
            for (JCImport imp : this.raw_imports) {
                java.nio.file.Path f;
                if (imp.exps != null) {
                    f = Paths.get(imp.exps, new String[0]).toAbsolutePath();
                } else {
                    try {
                        f = Misc.makeTemp("imports-" + this.runIdentifier());
                        OffCardVerifier.extractExps(project.resolveFile(imp.jar).toPath(), f);
                    }
                    catch (IOException e) {
                        throw new BuildException("Can not extract EXP files from JAR", (Throwable)e);
                    }
                }
                exps.add(f);
            }
            this.convert(applet_folder, exps);
            String ln = Misc.lastName(this.package_name);
            String pkgPath = this.package_name.replace(".", File.separator);
            java.nio.file.Path pkgDir = applet_folder.resolve(pkgPath);
            java.nio.file.Path jcsrc = pkgDir.resolve("javacard");
            java.nio.file.Path cap = jcsrc.resolve(ln + ".cap");
            java.nio.file.Path exp = jcsrc.resolve(ln + ".exp");
            java.nio.file.Path jca = jcsrc.resolve(ln + ".jca");
            if (this.verify) {
                this.setTaskName("verify");
                OffCardVerifier verifier = OffCardVerifier.withSDK(this.jckit);
                exps.add(exp);
                exps.add(this.targetsdk.getExportDir());
                try {
                    verifier.verify(cap, new ArrayList<java.nio.file.Path>(exps));
                    this.log("Verification of " + cap + " passed", 2);
                }
                catch (IOException | VerifierError e) {
                    throw new BuildException("Verification of " + cap + " failed: " + e.getMessage());
                }
            }
            this.setTaskName("cap");
            try {
                if (!Files.exists(cap, new LinkOption[0])) {
                    throw new BuildException("Can not find CAP in " + jcsrc);
                }
                CAPFile capfile = CAPFile.fromBytes(Files.readAllBytes(cap));
                this.output_cap = this.capFileName(capfile, this.output_cap);
                java.nio.file.Path outCap = project.resolveFile(this.output_cap).toPath();
                if (this.strip) {
                    CAPFile.strip(cap);
                }
                Files.copy(cap, outCap, StandardCopyOption.REPLACE_EXISTING);
                this.log("CAP saved to " + outCap, 2);
                if (this.output_exp != null) {
                    this.setTaskName("exp");
                    if (!Files.exists(exp, new LinkOption[0])) {
                        throw new BuildException("Can not find EXP in " + jcsrc);
                    }
                    java.nio.file.Path outExp = project.resolveFile(this.output_exp).toPath();
                    java.nio.file.Path outExpPkg = outExp.resolve(pkgPath);
                    java.nio.file.Path outExpPkgJc = outExpPkg.resolve("javacard");
                    if (!Files.exists(outExpPkgJc, new LinkOption[0])) {
                        Files.createDirectories(outExpPkgJc, new FileAttribute[0]);
                    }
                    java.nio.file.Path exp_file = outExpPkgJc.resolve(exp.getFileName());
                    Files.copy(exp, exp_file, StandardCopyOption.REPLACE_EXISTING);
                    this.log("EXP saved to " + exp_file, 2);
                    exps.add(outExp);
                }
                if (this.output_jca != null) {
                    this.setTaskName("jca");
                    if (!Files.exists(jca, new LinkOption[0])) {
                        throw new BuildException("Can not find JCA in " + jcsrc);
                    }
                    outCap = project.resolveFile(this.output_jca).toPath();
                    Files.copy(jca, outCap, StandardCopyOption.REPLACE_EXISTING);
                    this.log("JCA saved to " + outCap.toAbsolutePath(), 2);
                }
                if (this.output_jar != null) {
                    this.setTaskName("jar");
                    File outJar = project.resolveFile(this.output_jar);
                    Jar jarz = new Jar();
                    jarz.setProject(project);
                    jarz.setTaskName("jar");
                    jarz.setDestFile(outJar);
                    FileSet jarcls = new FileSet();
                    jarcls.setDir(project.resolveFile(this.classes_path));
                    jarz.add((ResourceCollection)jarcls);
                    FileSet jarout = new FileSet();
                    jarout.setDir(applet_folder.toFile());
                    jarz.add((ResourceCollection)jarout);
                    jarz.execute();
                    this.log("JAR saved to " + outJar.getAbsolutePath(), 2);
                }
            }
            catch (IOException e) {
                e.printStackTrace();
                throw new BuildException("Can not copy output CAP, EXP or JCA", (Throwable)e);
            }
        }
        finally {
            Misc.cleanTemp();
        }
    }

    private String capFileName(CAPFile cap, String template) {
        String name = template;
        String n = cap.getAppletAIDs().size() == 1 && !cap.getFlags().contains("exports") ? Misc.lastName(this.raw_applets.get((int)0).klass) : cap.getPackageName();
        name = name.replace("%H", Misc.encodeHexString(cap.getLoadFileDataHash("SHA-256")).toLowerCase());
        name = name.replace("%h", Misc.encodeHexString(cap.getLoadFileDataHash("SHA-256")).toLowerCase().substring(0, 8));
        name = name.replace("%n", n);
        name = name.replace("%p", cap.getPackageName());
        name = name.replace("%a", cap.getPackageAID().toString());
        name = name.replace("%v", "v" + cap.getPackageVersion());
        name = name.replace("%j", cap.guessJavaCardVersion().orElse("unknown"));
        name = name.replace("%g", cap.guessGlobalPlatformVersion().orElse("unknown"));
        name = name.replace("%J", String.format("jdk%d", Misc.getCurrentJDKVersion()));
        return name;
    }

    static {
        loghack = Boolean.parseBoolean(System.getenv().getOrDefault("_ANT_JAVACARD_LOGHACK", "true"));
        if (loghack) {
            java.nio.file.Path logconf = Misc.makeTemp("logging").resolve("logging.properties");
            _logconf = logconf.toAbsolutePath().normalize().toString();
            try {
                Files.write(logconf, String.format("handlers = java.util.logging.ConsoleHandler%n.level = WARNING", new Object[0]).getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            }
            catch (IOException e) {
                System.err.println("Could not write temporary logging configuration: " + e.getMessage());
            }
        } else {
            _logconf = null;
            System.err.println("Loghack disabled");
        }
    }
}

