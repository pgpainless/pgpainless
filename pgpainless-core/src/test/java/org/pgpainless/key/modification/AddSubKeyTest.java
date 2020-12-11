/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class AddSubKeyTest {

    @Test
    public void testAddSubKey() throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        List<Long> keyIdsBefore = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = secretKeys.getPublicKeys(); it.hasNext(); ) {
            keyIdsBefore.add(it.next().getKeyID());
        }

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addSubKey(
                        KeySpec.getBuilder(ECDSA.fromCurve(EllipticCurve._P256))
                                .withKeyFlags(KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms(),
                        Passphrase.fromPassword("subKeyPassphrase"),
                        PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("password123")))
                .done();

        List<Long> keyIdsAfter = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = secretKeys.getPublicKeys(); it.hasNext(); ) {
            keyIdsAfter.add(it.next().getKeyID());
        }
        assertNotEquals(keyIdsAfter, keyIdsBefore);

        keyIdsAfter.removeAll(keyIdsBefore);
        long subKeyId = keyIdsAfter.get(0);

        PGPSecretKey subKey = secretKeys.getSecretKey(subKeyId);
        PGPPrivateKey privateKey = subKey.extractPrivateKey(
                PasswordBasedSecretKeyRingProtector
                        .forKey(subKey, Passphrase.fromPassword("subKeyPassphrase"))
                        .getDecryptor(subKeyId));
    }
}
