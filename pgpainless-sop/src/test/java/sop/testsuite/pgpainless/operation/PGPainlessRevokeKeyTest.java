// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import static java.lang.Thread.sleep;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import sop.SOP;
import sop.testsuite.operation.RevokeKeyTest;

public class PGPainlessRevokeKeyTest extends RevokeKeyTest {

    @ParameterizedTest
    @MethodSource("provideInstances") // from sop-java's RevokeKeyTest class
    @Override
    public void revokeUnprotectedKey(SOP sop) throws IOException {
        super.revokeUnprotectedKey(sop);

        byte[] key = sop.generateKey().generate().getBytes();
        try {
            sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        byte[] revokedKey = sop.revokeKey().keys(key).getBytes();

        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate certificate = api.readKey().parseCertificateOrKey(revokedKey);
        assertFalse(certificate.isSecretKey());
        assertTrue(certificate.getRevocation().isHardRevocation());
    }
}
