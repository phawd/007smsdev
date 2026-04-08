/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.tools.ant.BuildException
 */
package pro.javacard.ant;

import org.apache.tools.ant.BuildException;

public class HelpingBuildException
extends BuildException {
    private static final long serialVersionUID = -2365126253968479314L;

    public HelpingBuildException(String msg) {
        super(msg + "\n\nPLEASE READ https://github.com/martinpaljak/ant-javacard#readme");
    }
}

