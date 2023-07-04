// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring.impl;

import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.util.selection.keyring.SecretKeyRingSelectionStrategy;

/**
 * Implementations of {@link org.pgpainless.util.selection.keyring.KeyRingSelectionStrategy} which select key rings
 * based on the exact user-id.
 */
public final class ExactUserId {

    private ExactUserId() {

    }

    /**
     * {@link PublicKeyRingSelectionStrategy} which accepts {@link PGPPublicKeyRing PGPPublicKeyRings} if those
     * have a user-id which exactly matches the given <pre>identifier</pre>.
     */
    public static class PubRingSelectionStrategy extends PublicKeyRingSelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPPublicKeyRing keyRing) {
            List<String> userIds = KeyRingUtils.getUserIdsIgnoringInvalidUTF8(keyRing.getPublicKey());
            for (String userId : userIds) {
                if (userId.equals(identifier)) return true;
            }
            return false;
        }
    }

    /**
     * {@link SecretKeyRingSelectionStrategy} which accepts {@link PGPSecretKeyRing PGPSecretKeyRings} if those
     * have a user-id which exactly matches the given <pre>identifier</pre>.
     */
    public static class SecRingSelectionStrategy extends SecretKeyRingSelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPSecretKeyRing keyRing) {
            List<String> userIds = KeyRingUtils.getUserIdsIgnoringInvalidUTF8(keyRing.getPublicKey());
            for (String userId : userIds) {
                if (userId.equals(identifier)) return true;
            }
            return false;
        }
    }
}
