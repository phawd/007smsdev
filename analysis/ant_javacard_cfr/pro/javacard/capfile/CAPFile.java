/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.capfile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPPackage;
import pro.javacard.capfile.HexUtils;

public final class CAPFile {
    private static final String[] componentNames = new String[]{"Header", "Directory", "Import", "Applet", "Class", "Method", "StaticField", "Export", "ConstantPool", "RefLocation", "Descriptor", "Debug"};
    protected final Map<String, byte[]> entries;
    private final Map<AID, String> applets = new LinkedHashMap<AID, String>();
    private final List<CAPPackage> imports = new ArrayList<CAPPackage>();
    private CAPPackage pkg;
    private byte flags;
    private String cap_version;
    private Manifest manifest = null;
    private Document appletxml = null;
    private Path file;

    public static CAPFile fromStream(InputStream in) throws IOException {
        return new CAPFile(in);
    }

    public static CAPFile fromBytes(byte[] bytes) throws IOException {
        return CAPFile.fromStream(new ByteArrayInputStream(bytes));
    }

    public static CAPFile fromFile(Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path, new OpenOption[0]);){
            CAPFile cap = CAPFile.fromStream(in);
            cap.file = path;
            CAPFile cAPFile = cap;
            return cAPFile;
        }
    }

    public Optional<Path> getFile() {
        return Optional.ofNullable(this.file);
    }

    public byte[] getComponent(String name) {
        byte[] c = this.entries.get(CAPFile.pkg2jcdir(this.getPackageName()) + name + ".cap");
        return c == null ? null : (byte[])c.clone();
    }

    public byte[] getMetaInfEntry(String name) {
        return this.entries.get("META-INF/" + name);
    }

    public Optional<byte[]> getZipComponent(String name) {
        return Optional.ofNullable(this.entries.get(name));
    }

    public void store(OutputStream to) throws IOException {
        try (ZipOutputStream out = new ZipOutputStream(to);){
            for (Map.Entry<String, byte[]> e : this.entries.entrySet()) {
                out.putNextEntry(new ZipEntry(e.getKey()));
                out.write(e.getValue());
                out.closeEntry();
            }
        }
    }

    protected CAPFile(InputStream in) throws IOException {
        byte[] imps;
        byte[] ai;
        try (ZipInputStream zip = new ZipInputStream(in);){
            this.entries = CAPFile.readEntries(zip);
        }
        byte[] mf = this.entries.get("META-INF/MANIFEST.MF");
        if (mf != null) {
            ByteArrayInputStream mfi = new ByteArrayInputStream(mf);
            this.manifest = new Manifest(mfi);
        }
        if ((ai = this.entries.get("APPLET-INF/applet.xml")) != null) {
            try {
                DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                this.appletxml = dBuilder.parse(new ByteArrayInputStream(ai));
                this.appletxml.getDocumentElement().normalize();
            }
            catch (ParserConfigurationException | SAXException e) {
                throw new IOException(e);
            }
        }
        String pkgname = null;
        for (String p : this.entries.keySet()) {
            if (!p.endsWith("Header.cap")) continue;
            pkgname = CAPFile.jcdir2pkg(p);
            break;
        }
        if (pkgname == null) {
            throw new IOException("Could not figure out the package name of the applet!");
        }
        byte[] header = this.entries.get(CAPFile.pkg2jcdir(pkgname) + "Header.cap");
        this.cap_version = String.format("%d.%d", header[8], header[7]);
        this.flags = header[9];
        this.pkg = new CAPPackage(new AID(header, 13, header[12]), header[11], header[10], pkgname);
        byte[] applet = this.getComponent("Applet");
        if (applet != null) {
            int offset = 4;
            for (int j = 0; j < (applet[3] & 0xFF); ++j) {
                byte len;
                AID appaid;
                if (!this.applets.containsKey(appaid = new AID(applet, offset, len = applet[offset++]))) {
                    this.applets.put(appaid, null);
                }
                offset += len + 2;
            }
        }
        if ((imps = this.getComponent("Import")) != null) {
            int offset = 4;
            for (int j = 0; j < (imps[3] & 0xFF); ++j) {
                AID aid = new AID(imps, offset + 3, imps[offset + 2]);
                CAPPackage p = new CAPPackage(aid, imps[offset + 1], imps[offset]);
                this.imports.add(p);
                offset += imps[offset + 2] + 3;
            }
        }
        if (this.appletxml != null) {
            NodeList apps = this.appletxml.getElementsByTagName("applet");
            for (int i = 0; i < apps.getLength(); ++i) {
                Element app = (Element)apps.item(i);
                String name = app.getElementsByTagName("applet-class").item(0).getTextContent();
                String aidstring = app.getElementsByTagName("applet-AID").item(0).getTextContent();
                AID aid = AID.fromString(aidstring.replace("//aid/", "").replace("/", ""));
                if (!this.applets.containsKey(aid)) {
                    throw new IOException("applet.xml contains missing applet " + aid);
                }
                this.applets.put(aid, name);
            }
        }
    }

    private static Map<String, byte[]> readEntries(ZipInputStream in) throws IOException {
        LinkedHashMap<String, byte[]> result = new LinkedHashMap<String, byte[]>();
        ZipEntry entry = in.getNextEntry();
        while (entry != null) {
            int c;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            while ((c = in.read(buf)) != -1) {
                bos.write(buf, 0, c);
            }
            result.put(entry.getName(), bos.toByteArray());
            entry = in.getNextEntry();
        }
        return Collections.unmodifiableMap(result);
    }

    public AID getPackageAID() {
        return this.pkg.aid;
    }

    public List<AID> getAppletAIDs() {
        ArrayList<AID> result = new ArrayList<AID>();
        result.addAll(this.applets.keySet());
        return result;
    }

    public String getPackageVersion() {
        return this.pkg.getVersionString();
    }

    public String getPackageName() {
        return this.pkg.getName().orElseThrow(() -> new IllegalStateException("No package name"));
    }

    public byte[] getCode() {
        return this._getCode(false);
    }

    @Deprecated
    public byte[] getCode(boolean includeDebug) {
        return this._getCode(includeDebug);
    }

    byte[] _getCode(boolean includeDebug) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (String name : componentNames) {
            byte[] c = this.getComponent(name);
            if (c == null || !includeDebug && (name.equals("Debug") || name.equals("Descriptor"))) continue;
            try {
                result.write(c);
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return result.toByteArray();
    }

    public byte[] getLoadFileDataHash(String hash) {
        try {
            return MessageDigest.getInstance(hash).digest(this.getCode());
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Not possible", e);
        }
    }

    @Deprecated
    public byte[] getLoadFileDataHash(String hash, boolean includeDebug) {
        try {
            return MessageDigest.getInstance(hash).digest(this._getCode(includeDebug));
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Not possible", e);
        }
    }

    public void dump(PrintStream out) {
        Optional<String> gpv = this.guessGlobalPlatformVersion();
        Optional<String> jcv = this.guessJavaCardVersion();
        String gpversion = gpv.isPresent() ? "/GlobalPlatform " + gpv.get() : "";
        out.println("CAP file (v" + this.cap_version + "), contains: " + String.join((CharSequence)", ", this.getFlags()) + " for JavaCard " + jcv.orElse("2.1.1?") + gpversion);
        out.printf("Package: %s %s v%s%n", this.pkg.getName().get(), this.pkg.getAid().toString(), this.pkg.getVersionString());
        for (Map.Entry<AID, String> applet : this.getApplets().entrySet()) {
            out.println("Applet:  " + (applet.getValue() == null ? "" : applet.getValue() + " ") + applet.getKey());
        }
        for (CAPPackage imp : this.getImports()) {
            out.println("Import:  " + imp);
        }
        if (this.manifest != null) {
            Attributes mains = this.manifest.getMainAttributes();
            Map<String, Attributes> ent = this.manifest.getEntries();
            if (ent.keySet().size() > 1) {
                throw new IllegalArgumentException("Too many elements in CAP manifest");
            }
            if (ent.keySet().size() == 1) {
                Attributes caps = ent.get(ent.keySet().toArray()[0]);
                String jdk_name = mains.getValue("Created-By");
                String cap_creation_time = caps.getValue("Java-Card-CAP-Creation-Time");
                String converter_version = caps.getValue("Java-Card-Converter-Version");
                String converter_provider = caps.getValue("Java-Card-Converter-Provider");
                out.println("Generated by " + converter_provider + " converter " + converter_version);
                out.println("On " + cap_creation_time + " with JDK " + jdk_name);
            }
        }
        out.println("Code size " + this.getCode().length + " bytes (" + this.getCode(true).length + " with debug)");
        out.println("SHA-256 " + HexUtils.bin2hex(this.getLoadFileDataHash("SHA-256")).toLowerCase());
        out.println("SHA-1   " + HexUtils.bin2hex(this.getLoadFileDataHash("SHA-1")).toLowerCase());
    }

    public List<String> getFlags() {
        return CAPFile.flags2strings(this.flags);
    }

    public static List<String> flags2strings(byte flags) {
        ArrayList<String> result = new ArrayList<String>();
        if ((flags & 1) == 1) {
            result.add("integers");
        }
        if ((flags & 2) == 2) {
            result.add("exports");
        }
        if ((flags & 4) == 4) {
            result.add("applets");
        }
        return result;
    }

    public List<CAPPackage> getImports() {
        return Collections.unmodifiableList(this.imports);
    }

    public Map<AID, String> getApplets() {
        return Collections.unmodifiableMap(this.applets);
    }

    public Optional<String> guessJavaCardVersion() {
        AID jf = new AID("A0000000620101");
        for (CAPPackage p : this.imports) {
            if (!p.aid.equals(jf)) continue;
            switch (p.minor) {
                case 0: {
                    return Optional.of("2.1.1");
                }
                case 1: {
                    return Optional.of("2.1.2");
                }
                case 2: {
                    return Optional.of("2.2.1");
                }
                case 3: {
                    return Optional.of("2.2.2");
                }
                case 4: {
                    return Optional.of("3.0.1");
                }
                case 5: {
                    return Optional.of("3.0.4");
                }
                case 6: {
                    return Optional.of("3.0.5");
                }
                case 8: {
                    return Optional.of("3.1.0");
                }
                case 9: {
                    return Optional.of("3.2.0");
                }
            }
            return Optional.of(String.format("unknown: %d.%d", p.major, p.minor));
        }
        AID js = new AID("A0000000620102");
        for (CAPPackage p : this.imports) {
            if (!p.aid.equals(js)) continue;
            switch (p.minor) {
                case 1: {
                    return Optional.of("2.1.1");
                }
                case 2: {
                    return Optional.of("2.2.1");
                }
                case 3: {
                    return Optional.of("2.2.2");
                }
                case 4: {
                    return Optional.of("3.0.1");
                }
                case 5: {
                    return Optional.of("3.0.4");
                }
                case 6: {
                    return Optional.of("3.0.5");
                }
                case 7: {
                    return Optional.of("3.1.0");
                }
            }
            return Optional.of(String.format("unknown: %d.%d", p.major, p.minor));
        }
        return Optional.empty();
    }

    public Optional<String> guessGlobalPlatformVersion() {
        AID jf = new AID("A00000015100");
        for (CAPPackage p : this.imports) {
            if (!p.aid.equals(jf) || p.major != 1) continue;
            if (p.minor == 0) {
                return Optional.of("2.1.1");
            }
            if (p.minor >= 1 && p.minor <= 4) {
                return Optional.of("2.2");
            }
            if (p.minor == 5 || p.minor == 6) {
                return Optional.of("2.2.1");
            }
            if (p.minor == 7) {
                return Optional.of("2.3.1+A");
            }
            return Optional.of(String.format("unknown: %d.%d", p.major, p.minor));
        }
        return Optional.empty();
    }

    private static String pkg2jcdir(String pkgname) {
        return pkgname.replace(".", "/") + "/javacard/";
    }

    private static String jcdir2pkg(String jcdir) {
        return jcdir.substring(0, jcdir.lastIndexOf("/javacard/")).replace('/', '.');
    }

    public static void uncheckedDelete(Path p) throws UncheckedIOException {
        try {
            Files.delete(p);
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static void strip(Path cap) throws IOException {
        HashMap<String, String> props = new HashMap<String, String>();
        props.put("create", "false");
        URI zip_disk = URI.create("jar:" + cap.toUri());
        try (FileSystem zipfs = FileSystems.newFileSystem(zip_disk, props);){
            List toDelete = Files.walk(zipfs.getPath("/", new String[0]), new FileVisitOption[0]).filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList());
            Collections.sort(toDelete, Collections.reverseOrder(Comparator.comparingInt(o -> o.toString().length())));
            toDelete.stream().forEach(CAPFile::uncheckedDelete);
        }
    }
}

