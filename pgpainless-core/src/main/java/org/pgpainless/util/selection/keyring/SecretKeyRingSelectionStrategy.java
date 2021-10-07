// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
