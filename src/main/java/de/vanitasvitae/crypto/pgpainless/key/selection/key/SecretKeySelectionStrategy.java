package de.vanitasvitae.crypto.pgpainless.key.selection.key;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.util.MultiMap;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 * Key Selection Strategy which accepts {@link PGPSecretKey}s that are accepted by the abstract method
 * {@link #accept(Object, Object)}.
 *
 * @param <O> Type that describes the owner of the key.
 */
public abstract class SecretKeySelectionStrategy<O> implements KeySelectionStrategy<PGPSecretKey, PGPSecretKeyRing, O> {

    @Override
    public Set<PGPSecretKey> selectKeysFromKeyRing(O identifier, PGPSecretKeyRing ring) {
        Set<PGPSecretKey> keys = new HashSet<>();
        for (Iterator<PGPSecretKey> i = ring.getSecretKeys(); i.hasNext(); ) {
            PGPSecretKey key = i.next();
            if (accept(identifier, key)) keys.add(key);
        }
        return keys;
    }

    @Override
    public MultiMap<O, PGPSecretKey> selectKeysFromKeyRings(MultiMap<O, PGPSecretKeyRing> keyRings) {
        MultiMap<O, PGPSecretKey> keys = new MultiMap<>();
        for (O identifier : keyRings.keySet()) {
            for (PGPSecretKeyRing ring : keyRings.get(identifier)) {
                keys.put(identifier, selectKeysFromKeyRing(identifier, ring));
            }
        }
        return keys;
    }
}
