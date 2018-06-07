package de.vanitasvitae.crypto.pgpainless.key.selection.key;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.util.MultiMap;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

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
