/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.util.selection.keyring;

import javax.annotation.Nonnull;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.util.MultiMap;

public abstract class SecretKeyRingSelectionStrategy<O> implements KeyRingSelectionStrategy<PGPSecretKeyRing, PGPSecretKeyRingCollection, O> {
    @Override
    public Set<PGPSecretKeyRing> selectKeyRingsFromCollection(O identifier, @Nonnull PGPSecretKeyRingCollection keyRingCollection) {
        Set<PGPSecretKeyRing> accepted = new HashSet<>();
        for (Iterator<PGPSecretKeyRing> i = keyRingCollection.getKeyRings(); i.hasNext(); ) {
            PGPSecretKeyRing ring = i.next();
            if (accept(identifier, ring)) accepted.add(ring);
        }
        return accepted;
    }

    @Override
    public MultiMap<O, PGPSecretKeyRing> selectKeyRingsFromCollections(@Nonnull MultiMap<O, PGPSecretKeyRingCollection> keyRingCollections) {
        MultiMap<O, PGPSecretKeyRing> keyRings = new MultiMap<>();
        for (O identifier : keyRingCollections.keySet()) {
            for (PGPSecretKeyRingCollection collection : keyRingCollections.get(identifier)) {
                keyRings.put(identifier, selectKeyRingsFromCollection(identifier, collection));
            }
        }
        return keyRings;
    }
}
