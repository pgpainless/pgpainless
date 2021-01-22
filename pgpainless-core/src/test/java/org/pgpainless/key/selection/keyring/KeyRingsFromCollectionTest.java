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
package org.pgpainless.key.selection.keyring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.selection.keyring.impl.ExactUserId;
import org.pgpainless.util.MultiMap;

public class KeyRingsFromCollectionTest {

    @Test
    public void selectSecretKeyRingFromSecretKeyRingCollectionTest() throws IOException, PGPException {
        PGPSecretKeyRing emil = TestKeys.getEmilSecretKeyRing();
        PGPSecretKeyRing juliet = TestKeys.getJulietSecretKeyRing();
        PGPSecretKeyRingCollection collection = new PGPSecretKeyRingCollection(Arrays.asList(emil, juliet));

        SecretKeyRingSelectionStrategy<String> strategy = new ExactUserId.SecRingSelectionStrategy();
        Set<PGPSecretKeyRing> secretKeyRings = strategy.selectKeyRingsFromCollection(TestKeys.JULIET_UID, collection);
        assertEquals(1, secretKeyRings.size());
        assertEquals(juliet.getPublicKey().getKeyID(), secretKeyRings.iterator().next().getPublicKey().getKeyID());
    }

    @Test
    public void selectSecretKeyRingMapFromSecretKeyRingCollectionMapTest() throws IOException, PGPException {
        PGPSecretKeyRing emil = TestKeys.getEmilSecretKeyRing();
        PGPSecretKeyRing juliet = TestKeys.getJulietSecretKeyRing();
        MultiMap<String, PGPSecretKeyRingCollection> map = new MultiMap<>();
        PGPSecretKeyRingCollection julietCollection = new PGPSecretKeyRingCollection(Arrays.asList(emil, juliet));
        map.put(TestKeys.JULIET_UID, julietCollection);
        PGPSecretKeyRingCollection emilCollection = new PGPSecretKeyRingCollection(Collections.singletonList(emil));
        map.put(TestKeys.EMIL_UID, emilCollection);
        assertEquals(2, julietCollection.size());
        map.put("invalidId", emilCollection);

        SecretKeyRingSelectionStrategy<String> strategy = new ExactUserId.SecRingSelectionStrategy();
        MultiMap<String, PGPSecretKeyRing> selected = strategy.selectKeyRingsFromCollections(map);
        assertEquals(1, selected.get(TestKeys.JULIET_UID).size());
        assertEquals(1, selected.get(TestKeys.EMIL_UID).size());
        assertNull(selected.get("invalidId"));
    }

    @Test
    public void selectPublicKeyRingFromPublicKeyRingCollectionTest() throws IOException, PGPException {
        PGPPublicKeyRing emil = TestKeys.getEmilPublicKeyRing();
        PGPPublicKeyRing juliet = TestKeys.getJulietPublicKeyRing();
        PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(Arrays.asList(emil, juliet));

        PublicKeyRingSelectionStrategy<String> strategy = new ExactUserId.PubRingSelectionStrategy();
        Set<PGPPublicKeyRing> publicKeyRings = strategy.selectKeyRingsFromCollection(TestKeys.JULIET_UID, collection);
        assertEquals(1, publicKeyRings.size());
        assertEquals(juliet.getPublicKey().getKeyID(), publicKeyRings.iterator().next().getPublicKey().getKeyID());
    }

    @Test
    public void selectPublicKeyRingMapFromPublicKeyRingCollectionMapTest() throws IOException, PGPException {
        PGPPublicKeyRing emil = TestKeys.getEmilPublicKeyRing();
        PGPPublicKeyRing juliet = TestKeys.getJulietPublicKeyRing();
        MultiMap<String, PGPPublicKeyRingCollection> map = new MultiMap<>();
        PGPPublicKeyRingCollection julietCollection = new PGPPublicKeyRingCollection(Arrays.asList(emil, juliet));
        map.put(TestKeys.JULIET_UID, julietCollection);
        PGPPublicKeyRingCollection emilCollection = new PGPPublicKeyRingCollection(Collections.singletonList(emil));
        map.put(TestKeys.EMIL_UID, emilCollection);
        assertEquals(2, julietCollection.size());
        map.put("invalidId", emilCollection);

        PublicKeyRingSelectionStrategy<String> strategy = new ExactUserId.PubRingSelectionStrategy();
        MultiMap<String, PGPPublicKeyRing> selected = strategy.selectKeyRingsFromCollections(map);
        assertEquals(1, selected.get(TestKeys.JULIET_UID).size());
        assertEquals(1, selected.get(TestKeys.EMIL_UID).size());
        assertNull(selected.get("invalidId"));
    }
}
