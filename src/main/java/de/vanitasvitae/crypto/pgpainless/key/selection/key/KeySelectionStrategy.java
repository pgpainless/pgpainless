package de.vanitasvitae.crypto.pgpainless.key.selection.key;

import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.util.MultiMap;

/**
 * Interface that describes a selection strategy for OpenPGP keys.
 * @param <K> Type of the Key
 * @param <R> Type of the KeyRing
 * @param <O> Type that describes the owner of this key
 */
public interface KeySelectionStrategy<K, R, O> {

    boolean accept(O identifier, K key);

    Set<K> selectKeysFromKeyRing(O identifier, R ring);

    MultiMap<O, K> selectKeysFromKeyRings(MultiMap<O, R> rings);

}
