package org.pgpainless.sop;

import java.io.IOException;

import org.pgpainless.util.ArmorUtils;

public class Print {

    public static String toString(byte[] bytes, boolean armor) throws IOException {
        if (armor) {
            return ArmorUtils.toAsciiArmoredString(bytes);
        } else {
            return new String(bytes, "UTF-8");
        }
    }
}
