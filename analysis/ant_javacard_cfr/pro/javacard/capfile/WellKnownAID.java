/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.capfile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import pro.javacard.capfile.AID;

public final class WellKnownAID {
    private static final Map<AID, String> javaCardRegistry = new LinkedHashMap<AID, String>();
    private static final Map<AID, String> wellKnownRegistry = new LinkedHashMap<AID, String>();

    private WellKnownAID() {
    }

    public static void load(InputStream in) {
        try {
            Properties props = new Properties();
            props.load(in);
            for (String k : props.stringPropertyNames()) {
                wellKnownRegistry.put(AID.fromString(k), props.getProperty(k));
            }
        }
        catch (ClassCastException e) {
            System.err.println("Invalid format: " + e.getMessage());
        }
        catch (IOException e) {
            System.out.println("Could not parse AID list: " + e.getMessage());
        }
    }

    public static void load(Path p) {
        if (!Files.exists(p, new LinkOption[0])) {
            return;
        }
        try (InputStream in = Files.newInputStream(p, new OpenOption[0]);){
            WellKnownAID.load(in);
        }
        catch (IOException e) {
            System.err.println("Could not parse AID list: " + e.getMessage());
        }
    }

    public static String getJavaCardName(AID aid) {
        return javaCardRegistry.get(aid);
    }

    public static Optional<String> getName(AID aid) {
        return Optional.ofNullable(wellKnownRegistry.getOrDefault(aid, javaCardRegistry.get(aid)));
    }

    static {
        javaCardRegistry.put(AID.fromString("A0000000620001"), "java.lang");
        javaCardRegistry.put(AID.fromString("A0000000620002"), "java.io");
        javaCardRegistry.put(AID.fromString("A0000000620003"), "java.rmi");
        javaCardRegistry.put(AID.fromString("A0000000620101"), "javacard.framework");
        javaCardRegistry.put(AID.fromString("A000000062010101"), "javacard.framework.service");
        javaCardRegistry.put(AID.fromString("A0000000620102"), "javacard.security");
        javaCardRegistry.put(AID.fromString("A0000000620201"), "javacardx.crypto");
        javaCardRegistry.put(AID.fromString("A0000000620202"), "javacardx.biometry");
        javaCardRegistry.put(AID.fromString("A0000000620203"), "javacardx.external");
        javaCardRegistry.put(AID.fromString("A0000000620204"), "javacardx.biometry1toN");
        javaCardRegistry.put(AID.fromString("A0000000620205"), "javacardx.security");
        javaCardRegistry.put(AID.fromString("A000000062020501"), "javacardx.security.cert");
        javaCardRegistry.put(AID.fromString("A000000062020502"), "javacardx.security.derivation");
        javaCardRegistry.put(AID.fromString("A000000062020503"), "javacardx.security.util");
        javaCardRegistry.put(AID.fromString("A000000062020801"), "javacardx.framework.util");
        javaCardRegistry.put(AID.fromString("A00000006202080101"), "javacardx.framework.util.intx");
        javaCardRegistry.put(AID.fromString("A000000062020802"), "javacardx.framework.math");
        javaCardRegistry.put(AID.fromString("A000000062020803"), "javacardx.framework.tlv");
        javaCardRegistry.put(AID.fromString("A000000062020804"), "javacardx.framework.string");
        javaCardRegistry.put(AID.fromString("A000000062020805"), "javacardx.framework.event");
        javaCardRegistry.put(AID.fromString("A000000062020806"), "javacardx.framework.nio");
        javaCardRegistry.put(AID.fromString("A000000062020807"), "javacardx.framework.time");
        javaCardRegistry.put(AID.fromString("A0000000620209"), "javacardx.apdu");
        javaCardRegistry.put(AID.fromString("A000000062020901"), "javacardx.apdu.util");
        wellKnownRegistry.put(AID.fromString("A00000015100"), "org.globalplatform");
        wellKnownRegistry.put(AID.fromString("A00000015102"), "org.globalplatform.contactless");
        wellKnownRegistry.put(AID.fromString("A0000000030000"), "visa.openplatform");
        wellKnownRegistry.put(AID.fromString("A0000001515350"), "SSD creation package");
        wellKnownRegistry.put(AID.fromString("A000000151535041"), "SSD creation applet");
        wellKnownRegistry.put(AID.fromString("A0000000090003FFFFFFFF8910710001"), "sim.access");
        wellKnownRegistry.put(AID.fromString("A0000000090003FFFFFFFF8910710002"), "sim.toolkit");
        wellKnownRegistry.put(AID.fromString("A0000000090005FFFFFFFF8916010000"), "uicc.hci.framework");
        wellKnownRegistry.put(AID.fromString("A0000000090005FFFFFFFF8916020100"), "uicc.hci.services.cardemulation");
        wellKnownRegistry.put(AID.fromString("A0000000090005FFFFFFFF8916020200"), "uicc.hci.services.connectivity");
        try (InputStream in = WellKnownAID.class.getResourceAsStream("aid_list.properties");){
            if (in != null) {
                WellKnownAID.load(in);
            }
        }
        catch (IOException e) {
            throw new RuntimeException("Can not load builtin list of AID-s: " + e.getMessage(), e);
        }
        Path p = Paths.get(System.getenv().getOrDefault("AID_LIST", Paths.get(System.getProperty("user.home"), ".apdu4j", "aid_list.properties").toString()), new String[0]);
        WellKnownAID.load(p);
    }
}

