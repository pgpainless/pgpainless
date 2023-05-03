// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info;

import java.util.Set;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public abstract class KeyAccessor {

    protected final KeyRingInfo info;
    protected final SubkeyIdentifier key;

    KeyAccessor(@Nonnull KeyRingInfo info, @Nonnull SubkeyIdentifier key) {
        this.info = info;
        this.key = key;
    }

    /**
     * Depending on the way we address the key (key-id or user-id), return the respective {@link PGPSignature}
     * which contains the algorithm preferences we are going to use.
     * <p>
     * If we address a key via its user-id, we want to rely on the algorithm preferences in the user-id certification,
     * while we would instead rely on those in the direct-key signature if we'd address the key by key-id.
     *
     * @return signature
     */
    @Nonnull
    public abstract PGPSignature getSignatureWithPreferences();

    /**
     * Return preferred symmetric key encryption algorithms.
     *
     * @return preferred symmetric algorithms
     */
    @Nonnull
    public Set<SymmetricKeyAlgorithm> getPreferredSymmetricKeyAlgorithms() {
        return SignatureSubpacketsUtil.parsePreferredSymmetricKeyAlgorithms(getSignatureWithPreferences());
    }

    /**
     * Return preferred hash algorithms.
     *
     * @return preferred hash algorithms
     */
    @Nonnull
    public Set<HashAlgorithm> getPreferredHashAlgorithms() {
        return SignatureSubpacketsUtil.parsePreferredHashAlgorithms(getSignatureWithPreferences());
    }

    /**
     * Return preferred compression algorithms.
     *
     * @return preferred compression algorithms
     */
    @Nonnull
    public Set<CompressionAlgorithm> getPreferredCompressionAlgorithms() {
        return SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(getSignatureWithPreferences());
    }

    /**
     * Address the key via a user-id (e.g. "Alice &lt;alice@wonderland.lit&gt;").
     * In this case we are sourcing preferred algorithms from the user-id certification first.
     */
    public static class ViaUserId extends KeyAccessor {

        private final String userId;

        /**
         * Access a key via user-id.
         *
         * @param info info about a key at a given date
         * @param key id of the subkey
         * @param userId user-id
         */
        public ViaUserId(@Nonnull KeyRingInfo info,
                         @Nonnull SubkeyIdentifier key,
                         @Nonnull String userId) {
            super(info, key);
            this.userId = userId;
        }

        @Override
        @Nonnull
        public PGPSignature getSignatureWithPreferences() {
            PGPSignature signature = info.getLatestUserIdCertification(userId);
            if (signature != null) {
                return signature;
            }
            throw new IllegalStateException("No valid user-id certification signature found for '" + userId + "'.");
        }
    }

    /**
     * Address the key via key-id.
     * In this case we are sourcing preferred algorithms from the keys direct-key signature first.
     */
    public static class ViaKeyId extends KeyAccessor {

        /**
         * Address the key via key-id.
         * @param info info about the key at a given date
         * @param key key-id
         */
        public ViaKeyId(@Nonnull KeyRingInfo info,
                        @Nonnull SubkeyIdentifier key) {
            super(info, key);
        }

        @Override
        @Nonnull
        public PGPSignature getSignatureWithPreferences() {
            String primaryUserId = info.getPrimaryUserId();
            // If the key is located by Key ID, the algorithm of the primary User ID of the key provides the
            // preferred symmetric algorithm.
            PGPSignature signature = null;
            if (primaryUserId != null) {
                signature = info.getLatestUserIdCertification(primaryUserId);
            }

            if (signature == null) {
                signature = info.getLatestDirectKeySelfSignature();
            }

            if (signature == null) {
                throw new IllegalStateException("No valid signature found.");
            }
            return signature;
        }
    }

    public static class SubKey extends KeyAccessor {

        public SubKey(@Nonnull KeyRingInfo info,
                      @Nonnull SubkeyIdentifier key) {
            super(info, key);
        }

        @Override
        @Nonnull
        public PGPSignature getSignatureWithPreferences() {
            PGPSignature signature;
            if (key.getPrimaryKeyId() == key.getSubkeyId()) {
                signature = info.getLatestDirectKeySelfSignature();
                if (signature == null && info.getPrimaryUserId() != null) {
                    signature = info.getLatestUserIdCertification(info.getPrimaryUserId());
                }
            } else {
                signature = info.getCurrentSubkeyBindingSignature(key.getSubkeyId());
            }

            if (signature == null) {
                throw new IllegalStateException("No valid signature found.");
            }
            return signature;
        }
    }
}
