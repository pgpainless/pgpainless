package de.vanitasvitae.crypto.pgpainless.key.selection.keyring;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.util.MultiMap;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public abstract class SecretKeyRingSelectionStrategy<O> implements KeyRingSelectionStrategy<PGPSecretKeyRing, PGPSecretKeyRingCollection, O> {
    @Override
    public Set<PGPSecretKeyRing> selectKeyRingsFromCollection(O identifier, PGPSecretKeyRingCollection keyRingCollection) {
        Set<PGPSecretKeyRing> accepted = new HashSet<>();
        for (Iterator<PGPSecretKeyRing> i = keyRingCollection.getKeyRings(); i.hasNext(); ) {
            PGPSecretKeyRing ring = i.next();
            if (accept(identifier, ring)) accepted.add(ring);
        }
        return accepted;
    }

    @Override
    public MultiMap<O, PGPSecretKeyRing> selectKeyRingsFromCollections(MultiMap<O, PGPSecretKeyRingCollection> keyRingCollections) {
        MultiMap<O, PGPSecretKeyRing> keyRings = new MultiMap<>();
        for (O identifier : keyRingCollections.keySet()) {
            for (PGPSecretKeyRingCollection collection : keyRingCollections.get(identifier)) {
                keyRings.put(identifier, selectKeyRingsFromCollection(identifier, collection));
            }
        }
        return keyRings;
    }
}
