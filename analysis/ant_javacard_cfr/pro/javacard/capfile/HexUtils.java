/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.capfile;

class HexUtils {
    private static final char[] UPPER_HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    HexUtils() {
    }

    public static String encodeHexString_imp(byte[] data) {
        int l = data.length;
        char[] out = new char[l << 1];
        int j = 0;
        for (int i = 0; i < l; ++i) {
            out[j++] = UPPER_HEX[(0xF0 & data[i]) >>> 4];
            out[j++] = UPPER_HEX[0xF & data[i]];
        }
        return new String(out);
    }

    public static byte[] decodeHexString_imp(String str) {
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
            if (f < 0) {
                throw new IllegalArgumentException("Illegal hex: " + data[j]);
            }
            if ((f |= Character.digit(data[++j], 16)) < 0) {
                throw new IllegalArgumentException("Illegal hex: " + data[j]);
            }
            ++j;
            out[i] = (byte)(f & 0xFF);
            ++i;
        }
        return out;
    }

    public static byte[] hex2bin(String hex) {
        return HexUtils.decodeHexString_imp(hex);
    }

    public static String bin2hex(byte[] bin) {
        return HexUtils.encodeHexString_imp(bin);
    }

    public static byte[] stringToBin(String s) {
        s = s.toUpperCase().replaceAll(" ", "").replaceAll(":", "");
        s = s.replaceAll("0X", "").replaceAll("\n", "").replaceAll("\t", "");
        s = s.replaceAll(";", "");
        return HexUtils.decodeHexString_imp(s);
    }
}

