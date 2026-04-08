/*
 * Decompiled with CFR 0.152.
 */
package pro.javacard.capfile;

import java.util.Objects;
import java.util.Optional;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.WellKnownAID;

public final class CAPPackage {
    final AID aid;
    final int major;
    final int minor;
    final String name;

    public CAPPackage(AID aid, int major, int minor) {
        this(aid, major, minor, null);
    }

    public CAPPackage(AID aid, int major, int minor, String name) {
        this.aid = aid;
        this.major = major;
        this.minor = minor;
        this.name = name;
    }

    public boolean equals(Object other) {
        if (other instanceof CAPPackage) {
            CAPPackage o = (CAPPackage)other;
            return this.aid.equals(o.aid) && this.major == o.major && this.minor == o.minor;
        }
        return false;
    }

    public int hashCode() {
        return Objects.hash(this.aid, this.major, this.minor);
    }

    public String toString() {
        return String.format("%-32s v%d.%d %s", this.aid, this.major, this.minor, this.getName().orElse(WellKnownAID.getName(this.aid).orElse("(unknown)")));
    }

    public String getVersionString() {
        return String.format("%d.%d", this.major, this.minor);
    }

    public AID getAid() {
        return this.aid;
    }

    public int getMinor() {
        return this.minor;
    }

    public int getMajor() {
        return this.major;
    }

    public Optional<String> getName() {
        return Optional.ofNullable(this.name);
    }
}

