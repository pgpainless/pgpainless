// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import sop.SOP;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RevokeKeyTest {

    private static SOP sop;

    @BeforeAll
    public static void setup() {
        sop = new SOPImpl();
    }

    @Test
    public void revokeV6CertResultsInMinimalRevCert() throws IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey v6Key = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@pgpainless.org>");
        assertEquals(3, v6Key.getKeys().size());

        byte[] revoked = sop.revokeKey()
                .keys(v6Key.getEncoded())
                .getBytes();

        OpenPGPCertificate revocationCert = api.readKey().parseCertificate(revoked);
        assertEquals(1, revocationCert.getKeys().size(),
                "V6 keys are revoked using a minimal revocation cert," +
                        " consisting only of the primary key and a rev sig.");
    }
}
