// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring.impl;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.util.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.util.selection.keyring.SecretKeyRingSelectionStrategy;

/**
 * Implementations of {@link org.pgpainless.util.selection.keyring.KeyRingSelectionStrategy} which accept all keyRings.
 */
public final class Wildcard {

    private Wildcard() {

    }

    public static class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            return true;
        }
    }

    public static class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            return true;
        }
    }
}
