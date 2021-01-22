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
package org.pgpainless.key.selection.key;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.selection.key.impl.EncryptionKeySelectionStrategy;
import org.pgpainless.key.selection.key.impl.HasAnyKeyFlagSelectionStrategy;
import org.pgpainless.key.selection.key.util.Or;

public class AndOrSelectionStrategyTest {

    @Test
    public void testOr() throws IOException, PGPException {
        PGPSecretKeyRing ring = TestKeys.getEmilSecretKeyRing();
        Iterator<PGPSecretKey> secretKeys = ring.getSecretKeys();
        Or.SecKeySelectionStrategy secStrategy = new Or.SecKeySelectionStrategy(
                new HasAnyKeyFlagSelectionStrategy.SecretKey(KeyFlag.ENCRYPT_COMMS),
                new HasAnyKeyFlagSelectionStrategy.SecretKey(KeyFlag.ENCRYPT_STORAGE)
        );
        PGPSecretKey certSecKey = secretKeys.next();
        PGPSecretKey cryptSecKey = secretKeys.next();

        assertFalse(secStrategy.accept(certSecKey));
        assertTrue(secStrategy.accept(cryptSecKey));

        Iterator<PGPPublicKey> publicKeys = ring.getPublicKeys();
        Or.PubKeySelectionStrategy pubStrategy = new Or.PubKeySelectionStrategy(
                new EncryptionKeySelectionStrategy(KeyFlag.ENCRYPT_COMMS),
                new EncryptionKeySelectionStrategy(KeyFlag.ENCRYPT_STORAGE)
        );
        PGPPublicKey certPubKey = publicKeys.next();
        PGPPublicKey cryptPubKey = publicKeys.next();

        assertFalse(pubStrategy.accept(certPubKey));
        assertTrue(pubStrategy.accept(cryptPubKey));
    }
}
