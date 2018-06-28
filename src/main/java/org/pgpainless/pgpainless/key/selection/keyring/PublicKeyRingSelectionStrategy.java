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
package org.pgpainless.pgpainless.key.selection.keyring;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.pgpainless.pgpainless.util.MultiMap;

public abstract class PublicKeyRingSelectionStrategy<O> implements KeyRingSelectionStrategy<PGPPublicKeyRing, PGPPublicKeyRingCollection, O> {

    @Override
    public Set<PGPPublicKeyRing> selectKeyRingsFromCollection(O identifier, PGPPublicKeyRingCollection keyRingCollection) {
        Set<PGPPublicKeyRing> accepted = new HashSet<>();
        for (Iterator<PGPPublicKeyRing> i = keyRingCollection.getKeyRings(); i.hasNext(); ) {
            PGPPublicKeyRing ring = i.next();
            if (accept(identifier, ring)) accepted.add(ring);
        }
        return accepted;
    }

    @Override
    public MultiMap<O, PGPPublicKeyRing> selectKeyRingsFromCollections(MultiMap<O, PGPPublicKeyRingCollection> keyRingCollections) {
        MultiMap<O, PGPPublicKeyRing> keyRings = new MultiMap<>();
        for (O identifier : keyRingCollections.keySet()) {
            for (PGPPublicKeyRingCollection collection : keyRingCollections.get(identifier)) {
                keyRings.put(identifier, selectKeyRingsFromCollection(identifier, collection));
            }
        }
        return keyRings;
    }
}
