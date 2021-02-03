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
package org.pgpainless.util.selection.key;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.util.selection.key.impl.KeyBelongsToKeyRing;

public class KeyBelongsToKeyRingTest {

    @Test
    public void testStrategyOnlyAcceptsKeysThatBelongToKeyRing() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("test@test.test");
        Iterator<PGPPublicKey> iterator = secretKeys.getPublicKeys();
        PGPPublicKey primaryKey = iterator.next();
        PGPPublicKey subKey = iterator.next();

        KeyBelongsToKeyRing.PubkeySelectionStrategy strategy = new KeyBelongsToKeyRing.PubkeySelectionStrategy(primaryKey);
        assertTrue(strategy.accept(primaryKey));
        assertTrue(strategy.accept(subKey));

        PGPSecretKeyRing unrelatedKeys = TestKeys.getEmilSecretKeyRing();
        Iterator<PGPPublicKey> unrelated = unrelatedKeys.getPublicKeys();
        while (unrelated.hasNext()) {
            PGPPublicKey unrelatedKey = unrelated.next();
            assertFalse(strategy.accept(unrelatedKey));
        }
    }
}
