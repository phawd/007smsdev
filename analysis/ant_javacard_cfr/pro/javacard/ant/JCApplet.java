/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.tools.ant.BuildException
 */
package pro.javacard.ant;

import org.apache.tools.ant.BuildException;
import pro.javacard.ant.Misc;

public class JCApplet {
    String klass = null;
    byte[] aid = null;

    public void setClass(String msg) {
        this.klass = msg;
    }

    public void setAID(String msg) {
        try {
            this.aid = Misc.stringToBin(msg);
            if (this.aid.length < 5 || this.aid.length > 16) {
                throw new BuildException("Applet AID must be between 5 and 16 bytes: " + this.aid.length);
            }
        }
        catch (IllegalArgumentException e) {
            throw new BuildException("Not a valid applet AID: " + e.getMessage());
        }
    }
}

