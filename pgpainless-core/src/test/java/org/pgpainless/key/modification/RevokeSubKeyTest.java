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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class RevokeSubKeyTest {

    @Test
    public void revokeSukeyTest() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        Iterator<PGPSecretKey> keysIterator = secretKeys.iterator();
        PGPSecretKey primaryKey = keysIterator.next();
        PGPSecretKey subKey = keysIterator.next();

        assertFalse(subKey.getPublicKey().hasRevocation());

        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeSubKey(new OpenPgpV4Fingerprint(subKey), protector)
                .done();
        keysIterator = secretKeys.iterator();
        primaryKey = keysIterator.next();
        subKey = keysIterator.next();

        assertTrue(subKey.getPublicKey().hasRevocation());
    }
}
