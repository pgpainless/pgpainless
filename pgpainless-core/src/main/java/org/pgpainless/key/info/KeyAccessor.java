/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

    public KeyAccessor(KeyRingInfo info, SubkeyIdentifier key) {
        this.info = info;
        this.key = key;
    }

    /**
     * Depending on the way we address the key (key-id or user-id), return the respective {@link PGPSignature}
     * which contains the algorithm preferences we are going to use.
     *
     * If we address a key via its user-id, we want to rely on the algorithm preferences in the user-id certification,
     * while we would instead rely on those in the direct-key signature if we'd address the key by key-id.
     *
     * @return signature
     */
    public abstract @Nonnull PGPSignature getSignatureWithPreferences();

    /**
     * Return preferred symmetric key encryption algorithms.
     *
     * @return preferred symmetric algorithms
     */
    public Set<SymmetricKeyAlgorithm> getPreferredSymmetricKeyAlgorithms() {
        return SignatureSubpacketsUtil.parsePreferredSymmetricKeyAlgorithms(getSignatureWithPreferences());
    }

    /**
     * Return preferred hash algorithms.
     *
     * @return preferred hash algorithms
     */
    public Set<HashAlgorithm> getPreferredHashAlgorithms() {
        return SignatureSubpacketsUtil.parsePreferredHashAlgorithms(getSignatureWithPreferences());
    }

    /**
     * Return preferred compression algorithms.
     *
     * @return preferred compression algorithms
     */
    public Set<CompressionAlgorithm> getPreferredCompressionAlgorithms() {
        return SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(getSignatureWithPreferences());
    }

    /**
     * Address the key via a user-id (eg "Alice &lt;alice@wonderland.lit&gt;).
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
        public ViaUserId(KeyRingInfo info, SubkeyIdentifier key, String userId) {
            super(info, key);
            this.userId = userId;
        }

        @Override
        public @Nonnull PGPSignature getSignatureWithPreferences() {
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
        public ViaKeyId(KeyRingInfo info, SubkeyIdentifier key) {
            super(info, key);
        }

        @Override
        public @Nonnull PGPSignature getSignatureWithPreferences() {
            PGPSignature signature = info.getLatestDirectKeySelfSignature();
            if (signature != null) {
                return signature;
            }

            signature = info.getLatestUserIdCertification(info.getPrimaryUserId());
            if (signature == null) {
                throw new IllegalStateException("No valid signature found.");
            }
            return signature;
        }
    }
}
