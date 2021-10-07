// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring;

import javax.annotation.Nonnull;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.pgpainless.util.MultiMap;

public abstract class PublicKeyRingSelectionStrategy<O> implements KeyRingSelectionStrategy<PGPPublicKeyRing, PGPPublicKeyRingCollection, O> {

    @Override
    public Set<PGPPublicKeyRing> selectKeyRingsFromCollection(@Nonnull O identifier, @Nonnull PGPPublicKeyRingCollection keyRingCollection) {
        Set<PGPPublicKeyRing> accepted = new HashSet<>();
        for (Iterator<PGPPublicKeyRing> i = keyRingCollection.getKeyRings(); i.hasNext(); ) {
            PGPPublicKeyRing ring = i.next();
            if (accept(identifier, ring)) accepted.add(ring);
        }
        return accepted;
    }

    @Override
    public MultiMap<O, PGPPublicKeyRing> selectKeyRingsFromCollections(@Nonnull MultiMap<O, PGPPublicKeyRingCollection> keyRingCollections) {
        MultiMap<O, PGPPublicKeyRing> keyRings = new MultiMap<>();
        for (O identifier : keyRingCollections.keySet()) {
            for (PGPPublicKeyRingCollection collection : keyRingCollections.get(identifier)) {
                keyRings.put(identifier, selectKeyRingsFromCollection(identifier, collection));
            }
        }
        return keyRings;
    }
}
