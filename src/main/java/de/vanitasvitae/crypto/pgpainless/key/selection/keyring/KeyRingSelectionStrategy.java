package de.vanitasvitae.crypto.pgpainless.key.selection.keyring;

import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.util.MultiMap;

public interface KeyRingSelectionStrategy<R, C, O> {

    boolean accept(O identifier, R keyRing);

    Set<R> selectKeyRingsFromCollection(O identifier, C keyRingCollection);

    MultiMap<O, R> selectKeyRingsFromCollections(MultiMap<O, C> keyRingCollections);
}
