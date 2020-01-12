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
package org.pgpainless.key.selection.keyring;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.selection.keyring.impl.Whitelist;

public class WhitelistKeyRingSelectionStrategyTest {

    @Test
    public void testWithPublicKeys() throws IOException {
        Map<String, Set<Long>> ids = new ConcurrentHashMap<>();
        ids.put(TestKeys.JULIET_UID, Collections.singleton(TestKeys.JULIET_KEY_ID));
        Whitelist.PubRingSelectionStrategy<String> selectionStrategy = new Whitelist.PubRingSelectionStrategy<>(ids);

        PGPPublicKeyRing julietsKeys = TestKeys.getJulietPublicKeyRing();
        PGPPublicKeyRing romeosKeys = TestKeys.getRomeoPublicKeyRing();

        assertTrue(selectionStrategy.accept(TestKeys.JULIET_UID, julietsKeys));
        assertFalse(selectionStrategy.accept(TestKeys.JULIET_UID, romeosKeys));
        assertFalse(selectionStrategy.accept(TestKeys.ROMEO_UID, julietsKeys));
    }

    @Test
    public void testWithSecretKeys() throws IOException, PGPException {
        Map<String, Set<Long>> ids = new ConcurrentHashMap<>();
        ids.put(TestKeys.JULIET_UID, Collections.singleton(TestKeys.JULIET_KEY_ID));
        Whitelist.SecRingSelectionStrategy<String> selectionStrategy = new Whitelist.SecRingSelectionStrategy<>(ids);

        PGPSecretKeyRing julietsKeys = TestKeys.getJulietSecretKeyRing();
        PGPSecretKeyRing romeosKeys = TestKeys.getRomeoSecretKeyRing();

        assertTrue(selectionStrategy.accept(TestKeys.JULIET_UID, julietsKeys));
        assertFalse(selectionStrategy.accept(TestKeys.JULIET_UID, romeosKeys));
        assertFalse(selectionStrategy.accept(TestKeys.ROMEO_UID, julietsKeys));
    }
}
