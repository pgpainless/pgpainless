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
