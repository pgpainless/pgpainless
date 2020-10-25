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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class AddUserIdTest {

    @Test
    public void addUserIdToExistingKeyRing() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit", "rabb1th0le");
        PGPSecretKeyRing secretKeys = keyRing.getSecretKeys();

        Iterator<String> userIds = secretKeys.getSecretKey().getPublicKey().getUserIDs();
        assertEquals("alice@wonderland.lit", userIds.next());
        assertFalse(userIds.hasNext());

        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("rabb1th0le"));
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("cheshirecat@wonderland.lit", protector)
                .done();

        userIds = secretKeys.getPublicKey().getUserIDs();
        assertEquals("alice@wonderland.lit", userIds.next());
        assertEquals("cheshirecat@wonderland.lit", userIds.next());
        assertFalse(userIds.hasNext());

        // CHECKSTYLE:OFF
        // System.out.println(KeyPrinter.toAsciiArmoredString(secretKeys));
        // CHECKSTYLE:ON
    }
}
