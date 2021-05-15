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
package org.pgpainless.policy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.NotationRegistry;

/**
 * Policy class used to configure acceptable algorithm suites etc.
 */
public final class Policy {

    private static Policy INSTANCE;

    private HashAlgorithmPolicy signatureHashAlgorithmPolicy =
            HashAlgorithmPolicy.defaultSignatureAlgorithmPolicy();
    private HashAlgorithmPolicy revocationSignatureHashAlgorithmPolicy =
            HashAlgorithmPolicy.defaultRevocationSignatureHashAlgorithmPolicy();
    private SymmetricKeyAlgorithmPolicy symmetricKeyAlgorithmPolicy =
            SymmetricKeyAlgorithmPolicy.defaultSymmetricKeyAlgorithmPolicy();
    private final NotationRegistry notationRegistry = new NotationRegistry();

    private Policy() {
    }

    /**
     * Return the singleton instance of PGPainless' policy.
     *
     * @return singleton instance
     */
    public static Policy getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new Policy();
        }
        return INSTANCE;
    }

    /**
     * Return the hash algorithm policy for signatures.
     * @return hash algorithm policy
     */
    public HashAlgorithmPolicy getSignatureHashAlgorithmPolicy() {
        return signatureHashAlgorithmPolicy;
    }

    /**
     * Set a custom hash algorithm policy for signatures.
     *
     * @param policy custom policy
     */
    public void setSignatureHashAlgorithmPolicy(HashAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.signatureHashAlgorithmPolicy = policy;
    }

    /**
     * Return the hash algorithm policy for revocations.
     * This policy is separate from {@link #getSignatureHashAlgorithmPolicy()}, as PGPainless by default uses a
     * less strict policy when it comes to acceptable algorithms.
     *
     * @return revocation signature hash algorithm policy
     */
    public HashAlgorithmPolicy getRevocationSignatureHashAlgorithmPolicy() {
        return revocationSignatureHashAlgorithmPolicy;
    }

    /**
     * Set a custom hash algorithm policy for revocations.
     *
     * @param policy custom policy
     */
    public void setRevocationSignatureHashAlgorithmPolicy(HashAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.revocationSignatureHashAlgorithmPolicy = policy;
    }

    /**
     * Return the symmetric encryption algorithm policy.
     * This policy defines which symmetric algorithms are acceptable.
     *
     * @return symmetric algorithm policy
     */
    public SymmetricKeyAlgorithmPolicy getSymmetricKeyAlgorithmPolicy() {
        return symmetricKeyAlgorithmPolicy;
    }

    /**
     * Set a custom symmetric encryption algorithm policy.
     *
     * @param policy custom policy
     */
    public void setSymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.symmetricKeyAlgorithmPolicy = policy;
    }

    public static final class SymmetricKeyAlgorithmPolicy {

        private final SymmetricKeyAlgorithm defaultSymmetricKeyAlgorithm;
        private final List<SymmetricKeyAlgorithm> acceptableSymmetricKeyAlgorithms;

        public SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm defaultSymmetricKeyAlgorithm, List<SymmetricKeyAlgorithm> acceptableSymmetricKeyAlgorithms) {
            this.defaultSymmetricKeyAlgorithm = defaultSymmetricKeyAlgorithm;
            this.acceptableSymmetricKeyAlgorithms = Collections.unmodifiableList(acceptableSymmetricKeyAlgorithms);
        }

        /**
         * Return the default symmetric key algorithm.
         * This algorithm is used as a fallback when no consensus about symmetric algorithms can be reached.
         *
         * @return default symmetric encryption algorithm
         */
        public SymmetricKeyAlgorithm getDefaultSymmetricKeyAlgorithm() {
            return defaultSymmetricKeyAlgorithm;
        }

        /**
         * Return true if the given symmetric encryption algorithm is acceptable by this policy.
         *
         * @param algorithm algorithm
         * @return true if algorithm is acceptable, false otherwise
         */
        public boolean isAcceptable(SymmetricKeyAlgorithm algorithm) {
            return acceptableSymmetricKeyAlgorithms.contains(algorithm);
        }

        /**
         * Return true if the given symmetric encryption algorithm is acceptable by this policy.
         *
         * @param algorithmId algorithm
         * @return true if algorithm is acceptable, false otherwise
         */
        public boolean isAcceptable(int algorithmId) {
            SymmetricKeyAlgorithm algorithm = SymmetricKeyAlgorithm.fromId(algorithmId);
            return isAcceptable(algorithm);
        }

        /**
         * The default symmetric encryption algorithm policy of PGPainless.
         *
         * @return default symmetric encryption algorithm policy
         */
        public static SymmetricKeyAlgorithmPolicy defaultSymmetricKeyAlgorithmPolicy() {
            return new SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256, Arrays.asList(
                    SymmetricKeyAlgorithm.IDEA,
                    SymmetricKeyAlgorithm.CAST5,
                    SymmetricKeyAlgorithm.BLOWFISH,
                    SymmetricKeyAlgorithm.AES_128,
                    SymmetricKeyAlgorithm.AES_192,
                    SymmetricKeyAlgorithm.AES_256,
                    SymmetricKeyAlgorithm.TWOFISH,
                    SymmetricKeyAlgorithm.CAMELLIA_128,
                    SymmetricKeyAlgorithm.CAMELLIA_192,
                    SymmetricKeyAlgorithm.CAMELLIA_256
            ));
        }
    }

    public static final class HashAlgorithmPolicy {

        private final HashAlgorithm defaultHashAlgorithm;
        private final List<HashAlgorithm> acceptableHashAlgorithms;

        public HashAlgorithmPolicy(HashAlgorithm defaultHashAlgorithm, List<HashAlgorithm> acceptableHashAlgorithms) {
            this.defaultHashAlgorithm = defaultHashAlgorithm;
            this.acceptableHashAlgorithms = Collections.unmodifiableList(acceptableHashAlgorithms);
        }

        /**
         * Return the default hash algorithm.
         * This algorithm is used as a fallback when no consensus about hash algorithms can be reached.
         *
         * @return default hash algorithm
         */
        public HashAlgorithm defaultHashAlgorithm() {
            return defaultHashAlgorithm;
        }

        /**
         * Return true if the the given hash algorithm is acceptable by this policy.
         *
         * @param hashAlgorithm hash algorithm
         * @return true if the hash algorithm is acceptable, false otherwise
         */
        public boolean isAcceptable(HashAlgorithm hashAlgorithm) {
            return acceptableHashAlgorithms.contains(hashAlgorithm);
        }

        /**
         * Return true if the the given hash algorithm is acceptable by this policy.
         *
         * @param algorithmId hash algorithm
         * @return true if the hash algorithm is acceptable, false otherwise
         */
        public boolean isAcceptable(int algorithmId) {
            HashAlgorithm algorithm = HashAlgorithm.fromId(algorithmId);
            return isAcceptable(algorithm);
        }

        /**
         * The default signature hash algorithm policy of PGPainless.
         * Note that this policy is only used for non-revocation signatures.
         * For revocation signatures {@link #defaultRevocationSignatureHashAlgorithmPolicy()} is used instead.
         *
         * @return default signature hash algorithm policy
         */
        public static HashAlgorithmPolicy defaultSignatureAlgorithmPolicy() {
            return new HashAlgorithmPolicy(HashAlgorithm.SHA512, Arrays.asList(
                    HashAlgorithm.SHA224,
                    HashAlgorithm.SHA256,
                    HashAlgorithm.SHA384,
                    HashAlgorithm.SHA512
            ));
        }

        /**
         * The default revocation signature hash algorithm policy of PGPainless.
         *
         * @return default revocation signature hash algorithm policy
         */
        public static HashAlgorithmPolicy defaultRevocationSignatureHashAlgorithmPolicy() {
            return new HashAlgorithmPolicy(HashAlgorithm.SHA512, Arrays.asList(
                    HashAlgorithm.RIPEMD160,
                    HashAlgorithm.SHA1,
                    HashAlgorithm.SHA224,
                    HashAlgorithm.SHA256,
                    HashAlgorithm.SHA384,
                    HashAlgorithm.SHA512
            ));
        }
    }

    /**
     * Return the {@link NotationRegistry} of PGPainless.
     * The notation registry is used to decide, whether or not a Notation is known or not.
     * Background: Critical unknown notations render signatures invalid.
     *
     * @return Notation registry
     */
    public NotationRegistry getNotationRegistry() {
        return notationRegistry;
    }
}
