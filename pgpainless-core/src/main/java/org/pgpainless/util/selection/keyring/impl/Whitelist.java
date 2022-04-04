// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring.impl;

import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.util.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.util.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.util.MultiMap;

/**
 * Implementations of {@link org.pgpainless.util.selection.keyring.KeyRingSelectionStrategy} which accept PGP KeyRings
 * based on a whitelist of acceptable keyIds.
 */
public final class Whitelist {

    private Whitelist() {

    }

    /**
     * {@link org.pgpainless.util.selection.keyring.KeyRingSelectionStrategy} which accepts
     * {@link PGPPublicKeyRing PGPPublicKeyRings} if the <pre>whitelist</pre> contains their primary key id.
     *
     * If the whitelist contains 123L for "alice@pgpainless.org", the key with primary key id 123L is
     * acceptable for "alice@pgpainless.org".
     *
     * @param <O> Type of identifier for {@link org.bouncycastle.openpgp.PGPPublicKeyRingCollection PGPPublicKeyRingCollections}.
     */
    public static class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public PubRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public PubRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this(new MultiMap<>(whitelist));
        }

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }
    }

    /**
     * {@link org.pgpainless.util.selection.keyring.KeyRingSelectionStrategy} which accepts
     * {@link PGPSecretKeyRing PGPSecretKeyRings} if the <pre>whitelist</pre> contains their primary key id.
     *
     * If the whitelist contains 123L for "alice@pgpainless.org", the key with primary key id 123L is
     * acceptable for "alice@pgpainless.org".
     *
     * @param <O> Type of identifier for {@link org.bouncycastle.openpgp.PGPSecretKeyRingCollection PGPSecretKeyRingCollections}.
     */
    public static class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public SecRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public SecRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this(new MultiMap<>(whitelist));
        }

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }

    }
}
