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
package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.info.KeyInfo;

public class BrainpoolKeyGeneration {

    @Test
    public void generateEcKeysTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        for (EllipticCurve curve : EllipticCurve.values()) {
            PGPSecretKeyRing secretKeys = generateKey(
                    KeySpec.getBuilder(KeyType.ECDSA(curve))
                            .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                            .withDefaultAlgorithms(),
                    KeySpec.getBuilder(KeyType.ECDH(curve))
                            .withKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                            .withDefaultAlgorithms(),
                    "Elliptic Curve <elliptic@curve.key>");

            assertEquals(PublicKeyAlgorithm.ECDSA, PublicKeyAlgorithm.fromId(secretKeys.getPublicKey().getAlgorithm()));
            PGPPublicKey publicKey = secretKeys.getPublicKey();
            assertEquals(curve.getName(), KeyInfo.getCurveName(publicKey));
        }
    }

    public PGPSecretKeyRing generateKey(KeySpec primaryKey, KeySpec subKey, String userId) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withSubKey(subKey)
                .withPrimaryKey(primaryKey)
                .withPrimaryUserId(userId)
                .withoutPassphrase()
                .build();
        return secretKeys;
    }
}
