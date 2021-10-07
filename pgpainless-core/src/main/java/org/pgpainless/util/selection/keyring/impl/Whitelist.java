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

public final class Whitelist {

    private Whitelist() {

    }

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
