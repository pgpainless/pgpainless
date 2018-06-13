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
package de.vanitasvitae.crypto.pgpainless;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

public abstract class KeyFilter {

    public Set<Long> filter(Set<Long> initialIdSet, PGPPublicKeyRingCollection collection) {
        Set<PGPPublicKeyRing> rings = new HashSet<>();
        for (Iterator<PGPPublicKeyRing> i = collection.getKeyRings(); i.hasNext();) {
            rings.add(i.next());
        }
        return filter(initialIdSet, rings, false);
    }

    public Set<Long> filter(Set<Long> initialIdSet, Set<PGPPublicKeyRing> rings, boolean boolToAvoidSameMethodErasure) {
        Set<PGPPublicKey> keys = new HashSet<>();
        for (PGPPublicKeyRing ring : rings) {
            for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext();) {
                keys.add(i.next());
            }
        }
        return filter(initialIdSet, keys);
    }

    public Set<Long> filter(Set<Long> initialIdSet, Set<PGPPublicKey> keys) {
        Set<Long> filteredIds = new HashSet<>();
        for (Long id : initialIdSet) {
            for (PGPPublicKey key : keys) {
                if (key.getKeyID() == id && filter(key)) {
                    filteredIds.add(id);
                }
            }
        }
        return filteredIds;
    }

    public abstract boolean filter(PGPPublicKey key);
}
