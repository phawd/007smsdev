/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.sdk;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Optional;

public final class ExportFileHelper {
    private ExportFileHelper() {
    }

    public static Optional<ExportFileVersion> getVersion(Path path) throws IOException {
        try (DataInputStream dis = new DataInputStream(Files.newInputStream(path, new OpenOption[0]));){
            int magic = dis.readInt();
            byte minor = dis.readByte();
            byte major = dis.readByte();
            if (magic != 16435934) {
                Optional<ExportFileVersion> optional = Optional.empty();
                return optional;
            }
            if (major != 2) {
                throw new IOException("Invalid major version: " + major);
            }
            if (minor == 1) {
                Optional<ExportFileVersion> optional = Optional.of(ExportFileVersion.V21);
                return optional;
            }
            if (minor == 3) {
                Optional<ExportFileVersion> optional = Optional.of(ExportFileVersion.V23);
                return optional;
            }
            throw new IOException("Invalid minor version: " + minor);
        }
    }

    public static enum ExportFileVersion {
        V21,
        V23;

    }
}

