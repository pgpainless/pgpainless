// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;

public class ConvertKeys {

    /**
     * This example demonstrates how to extract a public key certificate from a secret key.
     *
     * @throws PGPException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void secretKeyToCertificate() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        String userId = "alice@wonderland.lit";
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing(userId, null);
        // Extract certificate (public key) from secret key
        PGPPublicKeyRing certificate = KeyRingUtils.publicKeyRingFrom(secretKey);


        KeyRingInfo secretKeyInfo = PGPainless.inspectKeyRing(secretKey);
        assertTrue(secretKeyInfo.isSecretKey());
        KeyRingInfo certificateInfo = PGPainless.inspectKeyRing(certificate);
        assertFalse(certificateInfo.isSecretKey());
    }
}
