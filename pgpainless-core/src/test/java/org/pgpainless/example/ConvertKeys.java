/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
