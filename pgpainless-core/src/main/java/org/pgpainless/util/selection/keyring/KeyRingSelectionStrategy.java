// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring;

import java.util.Set;

import org.pgpainless.util.MultiMap;

/**
 *
 * @param <R> Type of {@link org.bouncycastle.openpgp.PGPKeyRing} ({@link org.bouncycastle.openpgp.PGPSecretKeyRing}
 *           or {@link org.bouncycastle.openpgp.PGPPublicKeyRing}).
 * @param <C> Type of key ring collection (e.g. {@link org.bouncycastle.openpgp.PGPSecretKeyRingCollection}
 *          or {@link org.bouncycastle.openpgp.PGPPublicKeyRingCollection}).
 * @param <O> Type of key identifier
 */
public interface KeyRingSelectionStrategy<R, C, O> {

    /**
     * Return true, if the filter accepts the given <pre>keyRing</pre> based on the given <pre>identifier</pre>.
     *
     * @param identifier identifier
     * @param keyRing key ring
     * @return acceptance
     */
    boolean accept(O identifier, R keyRing);

    /**
     * Iterate of the given <pre>keyRingCollection</pre> and return a {@link Set} of all acceptable
     * keyRings in the collection, based on the given <pre>identifier</pre>.
     *
     * @param identifier identifier
     * @param keyRingCollection collection
     * @return set of acceptable key rings
     */
    Set<R> selectKeyRingsFromCollection(O identifier, C keyRingCollection);

    /**
     * Iterate over all keyRings in the given {@link MultiMap} of keyRingCollections and return a new {@link MultiMap}
     * which for every identifier (key of the map) contains all acceptable keyRings based on that identifier.
     *
     * @param keyRingCollections MultiMap of identifiers and keyRingCollections.
     * @return MultiMap of identifiers and acceptable keyRings.
     */
    MultiMap<O, R> selectKeyRingsFromCollections(MultiMap<O, C> keyRingCollections);
}
