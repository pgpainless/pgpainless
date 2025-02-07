// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;

public class ConvertKeys {

    /**
     * This example demonstrates how to extract a public key certificate from a secret key.
     */
    @Test
    public void secretKeyToCertificate() {
        String userId = "alice@wonderland.lit";
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing(userId);
        // Extract certificate (public key) from secret key
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);


        KeyRingInfo secretKeyInfo = PGPainless.inspectKeyRing(secretKey);
        assertTrue(secretKeyInfo.isSecretKey());
        KeyRingInfo certificateInfo = PGPainless.inspectKeyRing(certificate);
        assertFalse(certificateInfo.isSecretKey());
    }
}
