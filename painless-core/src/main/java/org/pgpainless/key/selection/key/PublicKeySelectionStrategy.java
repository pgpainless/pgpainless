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
package org.pgpainless.key.selection.key;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.util.MultiMap;

/**
 * Key Selection Strategy which accepts {@link PGPPublicKey}s that are accepted by the abstract method
 * {@link #accept(Object, Object)}.
 *
 * @param <O> Type that describes the owner of the key.
 */
public abstract class PublicKeySelectionStrategy<O> implements KeySelectionStrategy<PGPPublicKey, PGPPublicKeyRing, O> {

    @Override
    public Set<PGPPublicKey> selectKeysFromKeyRing(O identifier, PGPPublicKeyRing ring) {
        Set<PGPPublicKey> keys = new HashSet<>();
        for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
            PGPPublicKey key = i.next();
            if (accept(identifier, key)) keys.add(key);
        }
        return keys;
    }

    @Override
    public MultiMap<O, PGPPublicKey> selectKeysFromKeyRings(MultiMap<O, PGPPublicKeyRing> keyRings) {
        MultiMap<O, PGPPublicKey> keys = new MultiMap<>();
        for (O identifier : keyRings.keySet()) {
            for (PGPPublicKeyRing ring : keyRings.get(identifier)) {
                keys.put(identifier, selectKeysFromKeyRing(identifier, ring));
            }
        }
        return keys;
    }
}
