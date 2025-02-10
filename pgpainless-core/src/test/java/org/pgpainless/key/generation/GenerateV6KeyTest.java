// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.OpenPGPKeyVersion;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class GenerateV6KeyTest {

    @Test
    public void generateModernV6Key() {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@example.org>")
                .getPGPSecretKeyRing();
        assertEquals(6, secretKey.getPublicKey().getVersion());
    }
}
