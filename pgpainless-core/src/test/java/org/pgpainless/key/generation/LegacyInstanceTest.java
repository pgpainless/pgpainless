// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

public class LegacyInstanceTest {

    @Test
    public void testKeyGenerationWithLegacyInstance() {
        PGPainless api = PGPainless.createLegacyInstance();
        OpenPGPKey key = api.generateKey().modernKeyRing("Alice <alice@example.org>");
        assertNull(key.getPrimarySecretKey().getAEADCipherSuitePreferences());
        assertFalse(key.getPrimarySecretKey().getFeatures().supportsSEIPDv2());
    }
}
