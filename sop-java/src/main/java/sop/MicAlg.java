// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

import java.io.OutputStream;
import java.io.PrintWriter;

public class MicAlg {

    private final String micAlg;

    public MicAlg(String micAlg) {
        if (micAlg == null) {
            throw new IllegalArgumentException("MicAlg String cannot be null.");
        }
        this.micAlg = micAlg;
    }

    public static MicAlg empty() {
        return new MicAlg("");
    }

    public static MicAlg fromHashAlgorithmId(int id) {
        switch (id) {
            case 1:
                return new MicAlg("pgp-md5");
            case 2:
                return new MicAlg("pgp-sha1");
            case 3:
                return new MicAlg("pgp-ripemd160");
            case 8:
                return new MicAlg("pgp-sha256");
            case 9:
                return new MicAlg("pgp-sha384");
            case 10:
                return new MicAlg("pgp-sha512");
            case 11:
                return new MicAlg("pgp-sha224");
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm ID: " + id);
        }
    }

    public String getMicAlg() {
        return micAlg;
    }

    public void writeTo(OutputStream outputStream) {
        PrintWriter pw = new PrintWriter(outputStream);
        pw.write(getMicAlg());
        pw.close();
    }
}
