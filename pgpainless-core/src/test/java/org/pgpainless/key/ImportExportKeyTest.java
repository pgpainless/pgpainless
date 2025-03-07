// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.util.TestAllImplementations;

public class ImportExportKeyTest {

    /**
     * Test the export and import of a key ring with sub keys.
     * @throws IOException in case of a IO error
     */
    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testExportImportPublicKeyRing() throws IOException {
        PGPPublicKeyRing publicKeys = TestKeys.getJulietPublicKeyRing();

        KeyFingerPrintCalculator calc = OpenPGPImplementation.getInstance().keyFingerPrintCalculator();
        byte[] bytes = publicKeys.getEncoded();
        PGPPublicKeyRing parsed = new PGPPublicKeyRing(bytes, calc);
        assertArrayEquals(publicKeys.getEncoded(), parsed.getEncoded());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testExportImportSecretKeyRing() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getRomeoSecretKeyRing();

        KeyFingerPrintCalculator calc = OpenPGPImplementation.getInstance().keyFingerPrintCalculator();
        byte[] bytes = secretKeys.getEncoded();
        PGPSecretKeyRing parsed = new PGPSecretKeyRing(bytes, calc);
        assertArrayEquals(secretKeys.getEncoded(), parsed.getEncoded());
        assertEquals(secretKeys.getPublicKey().getKeyID(), parsed.getPublicKey().getKeyID());
    }
}
