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
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.implementation.ImplementationFactory;

public class ImportExportKeyTest {

    /**
     * Test the export and import of a key ring with sub keys.
     * @throws IOException in case of a IO error
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testExportImportPublicKeyRing(ImplementationFactory implementationFactory) throws IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPPublicKeyRing publicKeys = TestKeys.getJulietPublicKeyRing();

        KeyFingerPrintCalculator calc = ImplementationFactory.getInstance().getKeyFingerprintCalculator();
        byte[] bytes = publicKeys.getEncoded();
        PGPPublicKeyRing parsed = new PGPPublicKeyRing(bytes, calc);
        assertArrayEquals(publicKeys.getEncoded(), parsed.getEncoded());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testExportImportSecretKeyRing(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing secretKeys = TestKeys.getRomeoSecretKeyRing();

        KeyFingerPrintCalculator calc = ImplementationFactory.getInstance().getKeyFingerprintCalculator();
        byte[] bytes = secretKeys.getEncoded();
        PGPSecretKeyRing parsed = new PGPSecretKeyRing(bytes, calc);
        assertArrayEquals(secretKeys.getEncoded(), parsed.getEncoded());
        assertEquals(secretKeys.getPublicKey().getKeyID(), parsed.getPublicKey().getKeyID());
    }
}
