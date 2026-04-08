/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.ant;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

final class Misc {
    private static final char[] LOWER_HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    static List<Path> temporary = new ArrayList<Path>();

    Misc() {
    }

    static String encodeHexString(byte[] data) {
        int l = data.length;
        char[] out = new char[l << 1];
        int j = 0;
        for (int i = 0; i < l; ++i) {
            out[j++] = LOWER_HEX[(0xF0 & data[i]) >>> 4];
            out[j++] = LOWER_HEX[0xF & data[i]];
        }
        return new String(out);
    }

    static byte[] decodeHexString(String str) {
        char[] data = str.toCharArray();
        int len = data.length;
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("Odd number of characters: " + str);
        }
        byte[] out = new byte[len >> 1];
        int i = 0;
        int j = 0;
        while (j < len) {
            int f = Character.digit(data[j], 16) << 4;
            f |= Character.digit(data[++j], 16);
            ++j;
            out[i] = (byte)(f & 0xFF);
            ++i;
        }
        return out;
    }

    static int getCurrentJDKVersion() {
        int dot;
        String v = System.getProperty("java.version", "0.0.0");
        if (v.startsWith("1.8.")) {
            v = "8." + v.substring(4);
        }
        int m = Integer.parseInt(v.substring(0, (dot = v.indexOf(".")) == -1 ? v.length() : dot));
        return m;
    }

    static String hexAID(byte[] aid) {
        StringJoiner hexaid = new StringJoiner(":");
        for (byte b : aid) {
            hexaid.add(String.format("0x%02X", b));
        }
        return hexaid.toString();
    }

    static void rmminusrf(Path path) {
        try {
            Files.walkFileTree(path, (FileVisitor<? super Path>)new SimpleFileVisitor<Path>(){

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException e) throws IOException {
                    if (e == null) {
                        Files.delete(dir);
                        return FileVisitResult.CONTINUE;
                    }
                    throw e;
                }
            });
        }
        catch (FileNotFoundException | NoSuchFileException iOException) {
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] stringToBin(String s) {
        s = s.toLowerCase().replaceAll(" ", "").replaceAll(":", "");
        s = s.replaceAll("0x", "").replaceAll("\n", "").replaceAll("\t", "");
        s = s.replaceAll(";", "");
        return Misc.decodeHexString(s);
    }

    static String lastName(String fqdn) {
        String ln = fqdn;
        if (ln.lastIndexOf(".") != -1) {
            ln = ln.substring(ln.lastIndexOf(".") + 1);
        }
        return ln;
    }

    static Path makeTemp(String sub) {
        try {
            if (System.getenv("ANT_JAVACARD_TMP") != null) {
                Path tmp = Paths.get(System.getenv("ANT_JAVACARD_TMP"), sub);
                Files.createDirectories(tmp, new FileAttribute[0]);
                return tmp;
            }
            Path p = Files.createTempDirectory("jccpro", new FileAttribute[0]);
            temporary.add(p);
            return p;
        }
        catch (IOException e) {
            throw new RuntimeException("Can not make temporary folder", e);
        }
    }

    static void cleanTemp() {
        if (System.getenv("ANT_JAVACARD_TMP") != null) {
            return;
        }
        if (Boolean.parseBoolean(System.getenv().getOrDefault("_ANT_JAVACARD_LITTER", "false"))) {
            System.err.println("Littering filesystem due to _ANT_JAVACARD_LITTER");
            return;
        }
        for (Path f : temporary) {
            if (!Files.exists(f, new LinkOption[0])) continue;
            Misc.rmminusrf(f);
        }
    }
}

