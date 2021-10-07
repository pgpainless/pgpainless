// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;

import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
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
    private SymmetricKeyAlgorithmPolicy symmetricKeyEncryptionAlgorithmPolicy =
            SymmetricKeyAlgorithmPolicy.defaultSymmetricKeyEncryptionAlgorithmPolicy();
    private SymmetricKeyAlgorithmPolicy symmetricKeyDecryptionAlgorithmPolicy =
            SymmetricKeyAlgorithmPolicy.defaultSymmetricKeyDecryptionAlgorithmPolicy();
    private CompressionAlgorithmPolicy compressionAlgorithmPolicy =
            CompressionAlgorithmPolicy.defaultCompressionAlgorithmPolicy();
    private PublicKeyAlgorithmPolicy publicKeyAlgorithmPolicy =
            PublicKeyAlgorithmPolicy.defaultPublicKeyAlgorithmPolicy();
    private final NotationRegistry notationRegistry = new NotationRegistry();

    private AlgorithmSuite keyGenerationAlgorithmSuite = AlgorithmSuite.getDefaultAlgorithmSuite();

    Policy() {
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
     * Return the symmetric encryption algorithm policy for encryption.
     * This policy defines which symmetric algorithms are acceptable when producing encrypted messages.
     *
     * @return symmetric algorithm policy for encryption
     */
    public SymmetricKeyAlgorithmPolicy getSymmetricKeyEncryptionAlgorithmPolicy() {
        return symmetricKeyEncryptionAlgorithmPolicy;
    }

    /**
     * Return the symmetric encryption algorithm policy for decryption.
     * This policy defines which symmetric algorithms are acceptable when decrypting encrypted messages.
     *
     * @return symmetric algorithm policy for decryption
     */
    public SymmetricKeyAlgorithmPolicy getSymmetricKeyDecryptionAlgorithmPolicy() {
        return symmetricKeyDecryptionAlgorithmPolicy;
    }

    /**
     * Set a custom symmetric encryption algorithm policy for encrypting messages.
     *
     * @param policy custom policy
     */
    public void setSymmetricKeyEncryptionAlgorithmPolicy(SymmetricKeyAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.symmetricKeyEncryptionAlgorithmPolicy = policy;
    }

    /**
     * Set a custom symmetric encryption algorithm policy for decrypting messages.
     *
     * @param policy custom policy
     */
    public void setSymmetricKeyDecryptionAlgorithmPolicy(SymmetricKeyAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.symmetricKeyDecryptionAlgorithmPolicy = policy;
    }

    public CompressionAlgorithmPolicy getCompressionAlgorithmPolicy() {
        return compressionAlgorithmPolicy;
    }

    public void setCompressionAlgorithmPolicy(CompressionAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Compression policy cannot be null.");
        }
        this.compressionAlgorithmPolicy = policy;
    }

    /**
     * Return the current public key algorithm policy.
     *
     * @return public key algorithm policy
     */
    public PublicKeyAlgorithmPolicy getPublicKeyAlgorithmPolicy() {
        return publicKeyAlgorithmPolicy;
    }

    /**
     * Set a custom public key algorithm policy.
     *
     * @param publicKeyAlgorithmPolicy custom policy
     */
    public void setPublicKeyAlgorithmPolicy(PublicKeyAlgorithmPolicy publicKeyAlgorithmPolicy) {
        if (publicKeyAlgorithmPolicy == null) {
            throw new NullPointerException("Public key algorithm policy cannot be null.");
        }
        this.publicKeyAlgorithmPolicy = publicKeyAlgorithmPolicy;
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
        public static SymmetricKeyAlgorithmPolicy defaultSymmetricKeyEncryptionAlgorithmPolicy() {
            return new SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256, Arrays.asList(
                    // Reject: Unencrypted, IDEA, TripleDES, CAST5
                    SymmetricKeyAlgorithm.AES_256,
                    SymmetricKeyAlgorithm.AES_192,
                    SymmetricKeyAlgorithm.AES_128,
                    SymmetricKeyAlgorithm.BLOWFISH,
                    SymmetricKeyAlgorithm.TWOFISH,
                    SymmetricKeyAlgorithm.CAMELLIA_256,
                    SymmetricKeyAlgorithm.CAMELLIA_192,
                    SymmetricKeyAlgorithm.CAMELLIA_128
            ));
        }

        /**
         * The default symmetric decryption algorithm policy of PGPainless.
         *
         * @return default symmetric decryption algorithm policy
         */
        public static SymmetricKeyAlgorithmPolicy defaultSymmetricKeyDecryptionAlgorithmPolicy() {
            return new SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256, Arrays.asList(
                    // Reject: Unencrypted, IDEA, TripleDES
                    SymmetricKeyAlgorithm.CAST5,
                    SymmetricKeyAlgorithm.AES_256,
                    SymmetricKeyAlgorithm.AES_192,
                    SymmetricKeyAlgorithm.AES_128,
                    SymmetricKeyAlgorithm.BLOWFISH,
                    SymmetricKeyAlgorithm.TWOFISH,
                    SymmetricKeyAlgorithm.CAMELLIA_256,
                    SymmetricKeyAlgorithm.CAMELLIA_192,
                    SymmetricKeyAlgorithm.CAMELLIA_128
            ));
        }

        /**
         * Select the best acceptable algorithm from the options list.
         * The best algorithm is the first algorithm we encounter in our list of acceptable algorithms that
         * is also contained in the list of options.
         *
         *
         * @param options list of algorithm options
         * @return best
         */
        public SymmetricKeyAlgorithm selectBest(List<SymmetricKeyAlgorithm> options) {
            for (SymmetricKeyAlgorithm acceptable : acceptableSymmetricKeyAlgorithms) {
                if (options.contains(acceptable)) {
                    return acceptable;
                }
            }
            return null;
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

    public static final class CompressionAlgorithmPolicy {

        private final CompressionAlgorithm defaultCompressionAlgorithm;
        private final List<CompressionAlgorithm> acceptableCompressionAlgorithms;

        public CompressionAlgorithmPolicy(CompressionAlgorithm defaultCompressionAlgorithm,
                                          List<CompressionAlgorithm> acceptableCompressionAlgorithms) {
            this.defaultCompressionAlgorithm = defaultCompressionAlgorithm;
            this.acceptableCompressionAlgorithms = Collections.unmodifiableList(acceptableCompressionAlgorithms);
        }

        public CompressionAlgorithm defaultCompressionAlgorithm() {
            return defaultCompressionAlgorithm;
        }

        public boolean isAcceptable(int compressionAlgorithmTag) {
            return isAcceptable(CompressionAlgorithm.fromId(compressionAlgorithmTag));
        }

        public boolean isAcceptable(CompressionAlgorithm compressionAlgorithm) {
            return acceptableCompressionAlgorithms.contains(compressionAlgorithm);
        }

        public static CompressionAlgorithmPolicy defaultCompressionAlgorithmPolicy() {
            return new CompressionAlgorithmPolicy(CompressionAlgorithm.ZIP, Arrays.asList(
                    CompressionAlgorithm.UNCOMPRESSED,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.BZIP2,
                    CompressionAlgorithm.ZLIB
            ));
        }
    }

    public static final class PublicKeyAlgorithmPolicy {

        private final Map<PublicKeyAlgorithm, Integer> algorithmStrengths = new EnumMap<>(PublicKeyAlgorithm.class);

        public PublicKeyAlgorithmPolicy(Map<PublicKeyAlgorithm, Integer> minimalAlgorithmBitStrengths) {
            this.algorithmStrengths.putAll(minimalAlgorithmBitStrengths);
        }

        public boolean isAcceptable(int algorithmId, int bitStrength) {
            return isAcceptable(PublicKeyAlgorithm.fromId(algorithmId), bitStrength);
        }

        public boolean isAcceptable(PublicKeyAlgorithm algorithm, int bitStrength) {
            if (!algorithmStrengths.containsKey(algorithm)) {
                return false;
            }

            int minStrength = algorithmStrengths.get(algorithm);
            return bitStrength >= minStrength;
        }

        /**
         * Return PGPainless' default public key algorithm policy.
         * This policy is based upon recommendations made by the German Federal Office for Information Security (BSI).
         *
         * Basically this policy requires keys based on elliptic curves to have a bit strength of at least 250,
         * and keys based on prime number factorization / discrete logarithm problems to have a strength of at least 2000 bits.
         *
         * @see <a href="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf">
         *     BSI - Technical Guideline - Cryptographic Mechanisms: Recommendations and Key Lengths (2021-01)</a>
         * @see <a href="https://www.keylength.com/">BlueKrypt | Cryptographic Key Length Recommendation</a>
         *
         * @return default algorithm policy
         */
        public static PublicKeyAlgorithmPolicy defaultPublicKeyAlgorithmPolicy() {
            Map<PublicKeyAlgorithm, Integer> minimalBitStrengths = new EnumMap<>(PublicKeyAlgorithm.class);
            // §5.4.1
            minimalBitStrengths.put(PublicKeyAlgorithm.RSA_GENERAL, 2000);
            minimalBitStrengths.put(PublicKeyAlgorithm.RSA_SIGN, 2000);
            minimalBitStrengths.put(PublicKeyAlgorithm.RSA_ENCRYPT, 2000);
            // Note: ElGamal is not mentioned in the BSI document.
            //  We assume that the requirements are similar to other DH algorithms
            minimalBitStrengths.put(PublicKeyAlgorithm.ELGAMAL_ENCRYPT, 2000);
            minimalBitStrengths.put(PublicKeyAlgorithm.ELGAMAL_GENERAL, 2000);
            // §5.4.2
            minimalBitStrengths.put(PublicKeyAlgorithm.DSA, 2000);
            // §5.4.3
            minimalBitStrengths.put(PublicKeyAlgorithm.ECDSA, 250);
            // Note: EdDSA is not mentioned in the BSI document.
            //  We assume that the requirements are similar to other EC algorithms.
            minimalBitStrengths.put(PublicKeyAlgorithm.EDDSA, 250);
            // §7.2.1
            minimalBitStrengths.put(PublicKeyAlgorithm.DIFFIE_HELLMAN, 2000);
            // §7.2.2
            minimalBitStrengths.put(PublicKeyAlgorithm.ECDH, 250);
            minimalBitStrengths.put(PublicKeyAlgorithm.EC, 250);

            return new PublicKeyAlgorithmPolicy(minimalBitStrengths);
        }
    }

    /**
     * Return the {@link NotationRegistry} of PGPainless.
     * The notation registry is used to decide, whether a Notation is known or not.
     * Background: Critical unknown notations render signatures invalid.
     *
     * @return Notation registry
     */
    public NotationRegistry getNotationRegistry() {
        return notationRegistry;
    }

    /**
     * Return the current {@link AlgorithmSuite} which defines preferred algorithms used during key generation.
     * @return current algorithm suite
     */
    public @Nonnull AlgorithmSuite getKeyGenerationAlgorithmSuite() {
        return keyGenerationAlgorithmSuite;
    }

    /**
     * Set a custom {@link AlgorithmSuite} which defines preferred algorithms used during key generation.
     *
     * @param algorithmSuite custom algorithm suite
     */
    public void setKeyGenerationAlgorithmSuite(@Nonnull AlgorithmSuite algorithmSuite) {
        this.keyGenerationAlgorithmSuite = algorithmSuite;
    }
}
