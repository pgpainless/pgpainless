// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy

import java.util.*
import org.bouncycastle.openpgp.api.EncryptedDataPacketType
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.pgpainless.algorithm.*
import org.pgpainless.key.protection.KeyRingProtectionSettings
import org.pgpainless.util.DateUtil
import org.pgpainless.util.NotationRegistry

class Policy {

    val certificationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy
    val revocationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy
    val dataSignatureHashAlgorithmPolicy: HashAlgorithmPolicy
    val messageEncryptionAlgorithmPolicy: MessageEncryptionMechanismPolicy
    val messageDecryptionAlgorithmPolicy: MessageEncryptionMechanismPolicy
    val compressionAlgorithmPolicy: CompressionAlgorithmPolicy
    val publicKeyAlgorithmPolicy: PublicKeyAlgorithmPolicy
    val featurePolicy: FeaturePolicy = FeaturePolicy.defaultFeaturePolicy()
    val keyProtectionSettings: KeyRingProtectionSettings
    val notationRegistry: NotationRegistry
    val keyGenerationAlgorithmSuite: AlgorithmSuite

    constructor(
        certificationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy,
        revocationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy,
        dataSignatureHashAlgorithmPolicy: HashAlgorithmPolicy,
        messageEncryptionMechanismPolicy: MessageEncryptionMechanismPolicy,
        messageDecryptionMechanismPolicy: MessageEncryptionMechanismPolicy,
        compressionAlgorithmPolicy: CompressionAlgorithmPolicy,
        publicKeyAlgorithmPolicy: PublicKeyAlgorithmPolicy,
        keyProtectionSettings: KeyRingProtectionSettings,
        notationRegistry: NotationRegistry,
        keyGenerationAlgorithmSuite: AlgorithmSuite
    ) {
        this.certificationSignatureHashAlgorithmPolicy = certificationSignatureHashAlgorithmPolicy
        this.revocationSignatureHashAlgorithmPolicy = revocationSignatureHashAlgorithmPolicy
        this.dataSignatureHashAlgorithmPolicy = dataSignatureHashAlgorithmPolicy
        this.messageEncryptionAlgorithmPolicy = messageEncryptionMechanismPolicy
        this.messageDecryptionAlgorithmPolicy = messageDecryptionMechanismPolicy
        this.compressionAlgorithmPolicy = compressionAlgorithmPolicy
        this.publicKeyAlgorithmPolicy = publicKeyAlgorithmPolicy
        this.keyProtectionSettings = keyProtectionSettings
        this.notationRegistry = notationRegistry
        this.keyGenerationAlgorithmSuite = keyGenerationAlgorithmSuite
    }

    @Deprecated(
        "Constructors receiving SymmetricKeyAlgorithmPolicy objects are deprecated in favor of ones receiving MessageEncryptionMechanismPolicy objects.")
    constructor(
        certificationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy,
        revocationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy,
        dataSignatureHashAlgorithmPolicy: HashAlgorithmPolicy,
        symmetricKeyEncryptionAlgorithmPolicy: SymmetricKeyAlgorithmPolicy,
        symmetricKeyDecryptionAlgorithmPolicy: SymmetricKeyAlgorithmPolicy,
        compressionAlgorithmPolicy: CompressionAlgorithmPolicy,
        publicKeyAlgorithmPolicy: PublicKeyAlgorithmPolicy,
        keyProtectionSettings: KeyRingProtectionSettings,
        notationRegistry: NotationRegistry,
        keyGenerationAlgorithmSuite: AlgorithmSuite
    ) {
        this.certificationSignatureHashAlgorithmPolicy = certificationSignatureHashAlgorithmPolicy
        this.revocationSignatureHashAlgorithmPolicy = revocationSignatureHashAlgorithmPolicy
        this.dataSignatureHashAlgorithmPolicy = dataSignatureHashAlgorithmPolicy
        this.messageEncryptionAlgorithmPolicy =
            MessageEncryptionMechanismPolicy.rfc4880Plus9580PlusLibrePGP(
                symmetricKeyEncryptionAlgorithmPolicy)
        this.messageDecryptionAlgorithmPolicy =
            MessageEncryptionMechanismPolicy.rfc4880Plus9580PlusLibrePGP(
                symmetricKeyDecryptionAlgorithmPolicy)
        this.compressionAlgorithmPolicy = compressionAlgorithmPolicy
        this.publicKeyAlgorithmPolicy = publicKeyAlgorithmPolicy
        this.keyProtectionSettings = keyProtectionSettings
        this.notationRegistry = notationRegistry
        this.keyGenerationAlgorithmSuite = keyGenerationAlgorithmSuite
    }

    @Deprecated(
        "Constructors receiving SymmetricKeyAlgorithmPolicy objects are deprecated in favor of ones receiving MessageEncryptionMechanismPolicy objects.")
    constructor() :
        this(
            HashAlgorithmPolicy.smartCertificationSignatureHashAlgorithmPolicy(),
            HashAlgorithmPolicy.smartCertificationSignatureHashAlgorithmPolicy(),
            HashAlgorithmPolicy.smartDataSignatureHashAlgorithmPolicy(),
            SymmetricKeyAlgorithmPolicy.symmetricKeyEncryptionPolicy2022(),
            SymmetricKeyAlgorithmPolicy.symmetricKeyDecryptionPolicy2022(),
            CompressionAlgorithmPolicy.anyCompressionAlgorithmPolicy(),
            PublicKeyAlgorithmPolicy.rfc9580PublicKeyAlgorithmPolicy(),
            KeyRingProtectionSettings.secureDefaultSettings(),
            NotationRegistry(),
            AlgorithmSuite.defaultAlgorithmSuite)

    @Deprecated("Deprecated in favor of messageEncryptionAlgorithmPolicy")
    // TODO: Remove in 2.1
    val symmetricKeyEncryptionAlgorithmPolicy
        get() = messageEncryptionAlgorithmPolicy.symmetricAlgorithmPolicy

    @Deprecated("Deprecated in favor of messageDecryptionAlgorithmPolicy")
    // TODO: Remove in 2.1
    val symmetricKeyDecryptionAlgorithmPolicy
        get() = messageDecryptionAlgorithmPolicy.symmetricAlgorithmPolicy

    /**
     * Decide, whether to sanitize public key parameters when unlocking OpenPGP secret keys. OpenPGP
     * v4 keys are susceptible to a class of attacks, where an attacker with access to the locked
     * key material (e.g. a cloud email provider) might manipulate unprotected public key parameters
     * of the key, leading to potential secret key leakage.
     *
     * @see [Key Overwriting (KO) Attacks against OpenPGP](https://www.kopenpgp.com/)
     */
    var enableKeyParameterValidation = false

    fun copy() = Builder(this)

    fun isEnableKeyParameterValidation() = enableKeyParameterValidation

    /**
     * Create a HashAlgorithmPolicy which accepts all [HashAlgorithms][HashAlgorithm] from the given
     * map, if the queried usage date is BEFORE the respective termination date. A termination date
     * value of <pre>null</pre> means no termination, resulting in the algorithm being acceptable,
     * regardless of usage date.
     *
     * @param defaultHashAlgorithm default hash algorithm
     * @param acceptableHashAlgorithmsAndTerminationDates map of acceptable algorithms and their
     *   termination dates
     */
    class HashAlgorithmPolicy(
        val defaultHashAlgorithm: HashAlgorithm,
        val acceptableHashAlgorithmsAndTerminationDates: Map<HashAlgorithm, Date?>
    ) {

        /**
         * Create a [HashAlgorithmPolicy] which accepts all [HashAlgorithms][HashAlgorithm] listed
         * in the given list, regardless of usage date.
         *
         * @param defaultHashAlgorithm default hash algorithm (e.g. used as fallback if negotiation
         *   fails)
         * @param acceptableHashAlgorithms list of acceptable hash algorithms
         */
        constructor(
            defaultHashAlgorithm: HashAlgorithm,
            acceptableHashAlgorithms: List<HashAlgorithm>
        ) : this(defaultHashAlgorithm, acceptableHashAlgorithms.associateWith { null })

        fun isAcceptable(hashAlgorithm: HashAlgorithm) = isAcceptable(hashAlgorithm, Date())

        /**
         * Return true, if the given algorithm is acceptable for the given usage date.
         *
         * @param hashAlgorithm algorithm
         * @param referenceTime usage date (e.g. signature creation time)
         * @return acceptance
         */
        fun isAcceptable(hashAlgorithm: HashAlgorithm, referenceTime: Date): Boolean {
            if (!acceptableHashAlgorithmsAndTerminationDates.containsKey(hashAlgorithm))
                return false
            val terminationDate =
                acceptableHashAlgorithmsAndTerminationDates[hashAlgorithm] ?: return true
            return terminationDate > referenceTime
        }

        fun isAcceptable(algorithmId: Int) = isAcceptable(algorithmId, Date())

        fun isAcceptable(algorithmId: Int, referenceTime: Date): Boolean {
            val algorithm = HashAlgorithm.fromId(algorithmId) ?: return false
            return isAcceptable(algorithm, referenceTime)
        }

        fun defaultHashAlgorithm() = defaultHashAlgorithm

        companion object {
            // https://sequoia-pgp.org/blog/2023/02/01/202302-happy-sha1-day/
            // signature data which is not attacker-controlled is acceptable before 2023-02-01
            @JvmStatic
            fun smartCertificationSignatureHashAlgorithmPolicy() =
                HashAlgorithmPolicy(
                    HashAlgorithm.SHA512,
                    buildMap {
                        put(HashAlgorithm.SHA3_512, null)
                        put(HashAlgorithm.SHA3_512, null)
                        put(HashAlgorithm.SHA3_256, null)
                        put(HashAlgorithm.SHA512, null)
                        put(HashAlgorithm.SHA384, null)
                        put(HashAlgorithm.SHA256, null)
                        put(HashAlgorithm.SHA224, null)
                        put(
                            HashAlgorithm.RIPEMD160,
                            DateUtil.parseUTCDate("2023-02-01 00:00:00 UTC"))
                        put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2023-02-01 00:00:00 UTC"))
                        put(HashAlgorithm.MD5, DateUtil.parseUTCDate("1997-02-01 00:00:00 UTC"))
                    })

            @JvmStatic
            fun smartDataSignatureHashAlgorithmPolicy() = smartSignatureHashAlgorithmPolicy()

            @JvmStatic
            fun smartSignatureHashAlgorithmPolicy() =
                HashAlgorithmPolicy(
                    HashAlgorithm.SHA512,
                    buildMap {
                        put(HashAlgorithm.SHA3_512, null)
                        put(HashAlgorithm.SHA3_256, null)
                        put(HashAlgorithm.SHA512, null)
                        put(HashAlgorithm.SHA384, null)
                        put(HashAlgorithm.SHA256, null)
                        put(HashAlgorithm.SHA224, null)
                        put(
                            HashAlgorithm.RIPEMD160,
                            DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"))
                        put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"))
                        put(HashAlgorithm.MD5, DateUtil.parseUTCDate("1997-02-01 00:00:00 UTC"))
                    })

            /**
             * [HashAlgorithmPolicy] which only accepts signatures made using algorithms which are
             * acceptable according to 2022 standards.
             *
             * Particularly this policy only accepts algorithms from the SHA2 and SHA3 families.
             *
             * @return static signature algorithm policy
             */
            @JvmStatic
            fun static2022SignatureHashAlgorithmPolicy() =
                HashAlgorithmPolicy(
                    HashAlgorithm.SHA512,
                    listOf(
                        HashAlgorithm.SHA3_512,
                        HashAlgorithm.SHA3_256,
                        HashAlgorithm.SHA512,
                        HashAlgorithm.SHA384,
                        HashAlgorithm.SHA256,
                        HashAlgorithm.SHA224))

            /**
             * Hash algorithm policy for revocation signatures, which accepts SHA1 and SHA2
             * algorithms, as well as RIPEMD160.
             *
             * @return static revocation signature hash algorithm policy
             */
            @JvmStatic
            fun static2022RevocationSignatureHashAlgorithmPolicy() =
                HashAlgorithmPolicy(
                    HashAlgorithm.SHA512,
                    listOf(
                        HashAlgorithm.SHA3_512,
                        HashAlgorithm.SHA3_256,
                        HashAlgorithm.SHA512,
                        HashAlgorithm.SHA384,
                        HashAlgorithm.SHA256,
                        HashAlgorithm.SHA224,
                        HashAlgorithm.SHA1,
                        HashAlgorithm.RIPEMD160))
        }
    }

    abstract class MessageEncryptionMechanismPolicy(
        val symmetricAlgorithmPolicy: SymmetricKeyAlgorithmPolicy,
        val asymmetricFallbackMechanism: MessageEncryptionMechanism,
        val symmetricFallbackMechanism: MessageEncryptionMechanism = asymmetricFallbackMechanism
    ) {
        abstract fun isAcceptable(encryptionMechanism: MessageEncryptionMechanism): Boolean

        companion object {

            @JvmStatic
            fun rfc4880(
                symAlgPolicy: SymmetricKeyAlgorithmPolicy
            ): MessageEncryptionMechanismPolicy {
                return object :
                    MessageEncryptionMechanismPolicy(
                        symAlgPolicy,
                        MessageEncryptionMechanism.integrityProtected(
                            symAlgPolicy.defaultSymmetricKeyAlgorithm.algorithmId)) {
                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        return encryptionMechanism.mode == EncryptedDataPacketType.SEIPDv1 &&
                            symAlgPolicy.isAcceptable(encryptionMechanism.symmetricKeyAlgorithm)
                    }
                }
            }

            @JvmStatic
            fun rfc9580(
                symAlgPolicy: SymmetricKeyAlgorithmPolicy
            ): MessageEncryptionMechanismPolicy {
                return object :
                    MessageEncryptionMechanismPolicy(
                        symAlgPolicy,
                        MessageEncryptionMechanism.aead(
                            symAlgPolicy.defaultSymmetricKeyAlgorithm.algorithmId,
                            AEADAlgorithm.OCB.algorithmId)) {
                    val acceptableAEADAlgorithms =
                        listOf(AEADAlgorithm.OCB, AEADAlgorithm.GCM, AEADAlgorithm.EAX).map {
                            it.algorithmId
                        }

                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        return when (encryptionMechanism.mode) {
                            EncryptedDataPacketType.SEIPDv1 ->
                                symAlgPolicy.isAcceptable(encryptionMechanism.symmetricKeyAlgorithm)
                            EncryptedDataPacketType.SEIPDv2 ->
                                symAlgPolicy.isAcceptable(
                                    encryptionMechanism.symmetricKeyAlgorithm) &&
                                    acceptableAEADAlgorithms.contains(
                                        encryptionMechanism.aeadAlgorithm)
                            else -> false
                        }
                    }
                }
            }

            @JvmStatic
            fun librePgp(
                symAlgPolicy: SymmetricKeyAlgorithmPolicy
            ): MessageEncryptionMechanismPolicy {
                return object :
                    MessageEncryptionMechanismPolicy(
                        symAlgPolicy,
                        MessageEncryptionMechanism.integrityProtected(
                            symAlgPolicy.defaultSymmetricKeyAlgorithm.algorithmId)) {
                    val acceptableAEADAlgorithms = listOf(AEADAlgorithm.OCB).map { it.algorithmId }

                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        return when (encryptionMechanism.mode) {
                            EncryptedDataPacketType.SEIPDv1 ->
                                symAlgPolicy.isAcceptable(encryptionMechanism.symmetricKeyAlgorithm)
                            EncryptedDataPacketType.LIBREPGP_OED ->
                                symAlgPolicy.isAcceptable(
                                    encryptionMechanism.symmetricKeyAlgorithm) &&
                                    acceptableAEADAlgorithms.contains(
                                        encryptionMechanism.aeadAlgorithm)
                            else -> false
                        }
                    }
                }
            }

            @JvmStatic
            fun rfc4880Plus9580(
                symAlgPolicy: SymmetricKeyAlgorithmPolicy
            ): MessageEncryptionMechanismPolicy {
                val rfc4880 = rfc4880(symAlgPolicy)
                val rfc9580 = rfc9580(symAlgPolicy)
                return object :
                    MessageEncryptionMechanismPolicy(
                        symAlgPolicy,
                        rfc4880.asymmetricFallbackMechanism,
                        rfc4880.symmetricFallbackMechanism) {
                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        return rfc9580.isAcceptable(encryptionMechanism) ||
                            rfc4880.isAcceptable(encryptionMechanism)
                    }
                }
            }

            @JvmStatic
            fun rfc4880Plus9580PlusLibrePGP(
                symAlgPolicy: SymmetricKeyAlgorithmPolicy
            ): MessageEncryptionMechanismPolicy {
                return object :
                    MessageEncryptionMechanismPolicy(
                        symAlgPolicy,
                        MessageEncryptionMechanism.integrityProtected(
                            symAlgPolicy.defaultSymmetricKeyAlgorithm.algorithmId)) {
                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        val rfc4480 = rfc4880(symAlgPolicy)
                        val rfc9580 = rfc9580(symAlgPolicy)
                        val librePgp = librePgp(symAlgPolicy)

                        return rfc4480.isAcceptable(encryptionMechanism) ||
                            rfc9580.isAcceptable(encryptionMechanism) ||
                            librePgp.isAcceptable(encryptionMechanism)
                    }
                }
            }
        }
    }

    class SymmetricKeyAlgorithmPolicy(
        val defaultSymmetricKeyAlgorithm: SymmetricKeyAlgorithm,
        val acceptableSymmetricKeyAlgorithms: List<SymmetricKeyAlgorithm>
    ) {

        fun isAcceptable(algorithm: SymmetricKeyAlgorithm) =
            acceptableSymmetricKeyAlgorithms.contains(algorithm)

        fun isAcceptable(algorithmId: Int): Boolean {
            val algorithm = SymmetricKeyAlgorithm.fromId(algorithmId) ?: return false
            return isAcceptable(algorithm)
        }

        fun selectBest(options: List<SymmetricKeyAlgorithm>): SymmetricKeyAlgorithm? {
            for (acceptable in acceptableSymmetricKeyAlgorithms) {
                if (options.contains(acceptable)) {
                    return acceptable
                }
            }
            return null
        }

        companion object {

            /**
             * The default symmetric encryption algorithm policy of PGPainless.
             *
             * @return default symmetric encryption algorithm policy
             * @deprecated not expressive - will be removed in a future release
             */
            @JvmStatic
            @Deprecated(
                "Not expressive - will be removed in a future release",
                ReplaceWith("symmetricKeyEncryptionPolicy2022"))
            fun defaultSymmetricKeyEncryptionAlgorithmPolicy() = symmetricKeyEncryptionPolicy2022()

            /**
             * Policy for symmetric encryption algorithms in the context of message production
             * (encryption). This suite contains algorithms that are deemed safe to use in 2022.
             *
             * @return 2022 symmetric key encryption algorithm policy
             */
            @JvmStatic
            fun symmetricKeyEncryptionPolicy2022() =
                SymmetricKeyAlgorithmPolicy(
                    SymmetricKeyAlgorithm.AES_128,
                    // Reject: Unencrypted, IDEA, TripleDES, CAST5, Blowfish
                    listOf(
                        SymmetricKeyAlgorithm.AES_256,
                        SymmetricKeyAlgorithm.AES_192,
                        SymmetricKeyAlgorithm.AES_128,
                        SymmetricKeyAlgorithm.TWOFISH,
                        SymmetricKeyAlgorithm.CAMELLIA_256,
                        SymmetricKeyAlgorithm.CAMELLIA_192,
                        SymmetricKeyAlgorithm.CAMELLIA_128))

            /**
             * The default symmetric decryption algorithm policy of PGPainless.
             *
             * @return default symmetric decryption algorithm policy
             * @deprecated not expressive - will be removed in a future update
             */
            @JvmStatic
            @Deprecated(
                "not expressive - will be removed in a future update",
                ReplaceWith("symmetricKeyDecryptionPolicy2022()"))
            fun defaultSymmetricKeyDecryptionAlgorithmPolicy() = symmetricKeyDecryptionPolicy2022()

            /**
             * Policy for symmetric key encryption algorithms in the context of message consumption
             * (decryption). This suite contains algorithms that are deemed safe to use in 2022.
             *
             * @return 2022 symmetric key decryption algorithm policy
             */
            @JvmStatic
            fun symmetricKeyDecryptionPolicy2022() =
                SymmetricKeyAlgorithmPolicy(
                    SymmetricKeyAlgorithm.AES_128,
                    // Reject: Unencrypted, IDEA, TripleDES, Blowfish
                    listOf(
                        SymmetricKeyAlgorithm.AES_256,
                        SymmetricKeyAlgorithm.AES_192,
                        SymmetricKeyAlgorithm.AES_128,
                        SymmetricKeyAlgorithm.TWOFISH,
                        SymmetricKeyAlgorithm.CAMELLIA_256,
                        SymmetricKeyAlgorithm.CAMELLIA_192,
                        SymmetricKeyAlgorithm.CAMELLIA_128,
                        SymmetricKeyAlgorithm.CAST5))
        }
    }

    class CompressionAlgorithmPolicy(
        val defaultCompressionAlgorithm: CompressionAlgorithm,
        val acceptableCompressionAlgorithms: List<CompressionAlgorithm>
    ) {

        fun isAcceptable(algorithm: CompressionAlgorithm) =
            acceptableCompressionAlgorithms.contains(algorithm)

        fun isAcceptable(algorithmId: Int): Boolean {
            val algorithm = CompressionAlgorithm.fromId(algorithmId) ?: return false
            return isAcceptable(algorithm)
        }

        fun defaultCompressionAlgorithm() = defaultCompressionAlgorithm

        companion object {

            /**
             * Default [CompressionAlgorithmPolicy] of PGPainless. The default compression algorithm
             * policy accepts any compression algorithm.
             *
             * @return default algorithm policy
             * @deprecated not expressive - might be removed in a future release
             */
            @JvmStatic
            @Deprecated(
                "not expressive - might be removed in a future release",
                ReplaceWith("anyCompressionAlgorithmPolicy()"))
            fun defaultCompressionAlgorithmPolicy() = anyCompressionAlgorithmPolicy()

            /**
             * Policy that accepts any known compression algorithm and offers
             * [CompressionAlgorithm.ZIP] as default algorithm.
             *
             * @return compression algorithm policy
             */
            @JvmStatic
            fun anyCompressionAlgorithmPolicy() =
                CompressionAlgorithmPolicy(
                    CompressionAlgorithm.UNCOMPRESSED,
                    listOf(
                        CompressionAlgorithm.UNCOMPRESSED,
                        CompressionAlgorithm.ZIP,
                        CompressionAlgorithm.BZIP2,
                        CompressionAlgorithm.ZLIB))
        }
    }

    class PublicKeyAlgorithmPolicy(private val algorithmStrengths: Map<PublicKeyAlgorithm, Int>) {

        fun isAcceptable(algorithm: PublicKeyAlgorithm, bitStrength: Int): Boolean {
            return bitStrength >= (algorithmStrengths[algorithm] ?: return false)
        }

        fun isAcceptable(algorithmId: Int, bitStrength: Int): Boolean {
            val algorithm = PublicKeyAlgorithm.fromId(algorithmId) ?: return false
            return isAcceptable(algorithm, bitStrength)
        }

        companion object {

            /**
             * Return PGPainless' default public key algorithm policy.
             *
             * @return default algorithm policy
             * @deprecated not expressive - might be removed in a future release
             */
            @JvmStatic
            @Deprecated(
                "not expressive - might be removed in a future release",
                ReplaceWith("rfc9580PublicKeyAlgorithmPolicy()"))
            fun defaultPublicKeyAlgorithmPolicy() = rfc9580PublicKeyAlgorithmPolicy()

            /**
             * This policy is based upon recommendations made by the German Federal Office for
             * Information Security (BSI).
             *
             * Basically this policy requires keys based on elliptic curves to have a bit strength
             * of at least 250, and keys based on prime number factorization / discrete logarithm
             * problems to have a strength of at least 2000 bits.
             *
             * @return default algorithm policy
             * @see
             *   [BSI - Technical Guideline - Cryptographic Mechanisms: Recommendations and Key Lengths (2021-01)](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf)
             * @see
             *   [BlueKrypt | Cryptographic Key Length Recommendation](https://www.keylength.com/)
             */
            @JvmStatic
            fun bsi2021PublicKeyAlgorithmPolicy() =
                PublicKeyAlgorithmPolicy(
                    buildMap {
                        // §5.4.1
                        put(PublicKeyAlgorithm.RSA_GENERAL, 2000)
                        put(PublicKeyAlgorithm.RSA_SIGN, 2000)
                        put(PublicKeyAlgorithm.RSA_ENCRYPT, 2000)
                        // Note: ElGamal is not mentioned in the BSI document.
                        //  We assume that the requirements are similar to other DH algorithms
                        put(PublicKeyAlgorithm.ELGAMAL_ENCRYPT, 2000)
                        put(PublicKeyAlgorithm.ELGAMAL_GENERAL, 2000)
                        // §5.4.2
                        put(PublicKeyAlgorithm.DSA, 2000)
                        // §5.4.3
                        put(PublicKeyAlgorithm.ECDSA, 250)
                        // Note: EdDSA is not mentioned in the BSI document.
                        //  We assume that the requirements are similar to other EC algorithms.
                        put(PublicKeyAlgorithm.EDDSA_LEGACY, 250)
                        // §7.2.1
                        put(PublicKeyAlgorithm.DIFFIE_HELLMAN, 2000)
                        // §7.2.2
                        put(PublicKeyAlgorithm.ECDH, 250)
                        // Fixed lengths
                        put(PublicKeyAlgorithm.X25519, 256)
                        put(PublicKeyAlgorithm.ED25519, 256)
                        put(PublicKeyAlgorithm.X448, 448)
                        put(PublicKeyAlgorithm.ED448, 456)
                    })

            /** Public Key Algorithm Policy based upon recommendations from RFC9580. */
            fun rfc9580PublicKeyAlgorithmPolicy(): PublicKeyAlgorithmPolicy =
                PublicKeyAlgorithmPolicy(
                    buildMap {
                        // https://www.rfc-editor.org/rfc/rfc9580.html#section-12.4
                        put(PublicKeyAlgorithm.RSA_GENERAL, 2000)
                        // https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp
                        put(PublicKeyAlgorithm.EDDSA_LEGACY, 250)
                        // https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp
                        put(PublicKeyAlgorithm.ECDH, 250)
                        put(PublicKeyAlgorithm.ECDSA, 250)
                        // https://www.rfc-editor.org/rfc/rfc9580.html#name-eddsa
                        put(PublicKeyAlgorithm.X25519, 256)
                        put(PublicKeyAlgorithm.ED25519, 256)
                        put(PublicKeyAlgorithm.X448, 448)
                        put(PublicKeyAlgorithm.ED448, 456)
                    })
        }
    }

    class Builder(private val origin: Policy) {
        private var certificationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy =
            origin.certificationSignatureHashAlgorithmPolicy
        private var revocationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy =
            origin.revocationSignatureHashAlgorithmPolicy
        private var dataSignatureHashAlgorithmPolicy: HashAlgorithmPolicy =
            origin.dataSignatureHashAlgorithmPolicy
        private var messageEncryptionMechanismPolicy: MessageEncryptionMechanismPolicy =
            origin.messageEncryptionAlgorithmPolicy
        private var messageDecryptionMechanismPolicy: MessageEncryptionMechanismPolicy =
            origin.messageDecryptionAlgorithmPolicy
        private var compressionAlgorithmPolicy: CompressionAlgorithmPolicy =
            origin.compressionAlgorithmPolicy
        private var publicKeyAlgorithmPolicy: PublicKeyAlgorithmPolicy =
            origin.publicKeyAlgorithmPolicy
        private var keyProtectionSettings: KeyRingProtectionSettings = origin.keyProtectionSettings
        private var notationRegistry: NotationRegistry = origin.notationRegistry
        private var keyGenerationAlgorithmSuite: AlgorithmSuite = origin.keyGenerationAlgorithmSuite

        fun withCertificationSignatureHashAlgorithmPolicy(
            certificationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy
        ) = apply {
            this.certificationSignatureHashAlgorithmPolicy =
                certificationSignatureHashAlgorithmPolicy
        }

        fun withRevocationSignatureHashAlgorithmPolicy(
            revocationSignatureHashAlgorithmPolicy: HashAlgorithmPolicy
        ) = apply {
            this.revocationSignatureHashAlgorithmPolicy = revocationSignatureHashAlgorithmPolicy
        }

        fun withDataSignatureHashAlgorithmPolicy(
            dataSignatureHashAlgorithmPolicy: HashAlgorithmPolicy
        ) = apply { this.dataSignatureHashAlgorithmPolicy = dataSignatureHashAlgorithmPolicy }

        @Deprecated(
            "Usage of SymmetricKeyAlgorithmPolicy is deprecated in favor of MessageEncryptionMechanismPolicy.")
        // TODO: Remove in 2.1
        fun withSymmetricKeyEncryptionAlgorithmPolicy(
            symmetricKeyEncryptionAlgorithmPolicy: SymmetricKeyAlgorithmPolicy
        ) =
            withMessageEncryptionAlgorithmPolicy(
                MessageEncryptionMechanismPolicy.rfc4880Plus9580PlusLibrePGP(
                    symmetricKeyEncryptionAlgorithmPolicy))

        @Deprecated(
            "Usage of SymmetricKeyAlgorithmPolicy is deprecated in favor of MessageEncryptionMechanismPolicy.")
        // TODO: Remove in 2.1
        fun withSymmetricKeyDecryptionAlgorithmPolicy(
            symmetricKeyDecryptionAlgorithmPolicy: SymmetricKeyAlgorithmPolicy
        ) =
            withMessageDecryptionAlgorithmPolicy(
                MessageEncryptionMechanismPolicy.rfc4880Plus9580PlusLibrePGP(
                    symmetricKeyDecryptionAlgorithmPolicy))

        fun withMessageEncryptionAlgorithmPolicy(
            encryptionMechanismPolicy: MessageEncryptionMechanismPolicy
        ) = apply { messageEncryptionMechanismPolicy = encryptionMechanismPolicy }

        fun withMessageDecryptionAlgorithmPolicy(
            decryptionMechanismPolicy: MessageEncryptionMechanismPolicy
        ) = apply { messageDecryptionMechanismPolicy = decryptionMechanismPolicy }

        fun withCompressionAlgorithmPolicy(compressionAlgorithmPolicy: CompressionAlgorithmPolicy) =
            apply {
                this.compressionAlgorithmPolicy = compressionAlgorithmPolicy
            }

        fun withPublicKeyAlgorithmPolicy(publicKeyAlgorithmPolicy: PublicKeyAlgorithmPolicy) =
            apply {
                this.publicKeyAlgorithmPolicy = publicKeyAlgorithmPolicy
            }

        fun withKeyProtectionSettings(keyProtectionSettings: KeyRingProtectionSettings) = apply {
            this.keyProtectionSettings = keyProtectionSettings
        }

        fun withNotationRegistry(notationRegistry: NotationRegistry) = apply {
            this.notationRegistry = notationRegistry
        }

        fun withKeyGenerationAlgorithmSuite(keyGenerationAlgorithmSuite: AlgorithmSuite) = apply {
            this.keyGenerationAlgorithmSuite = keyGenerationAlgorithmSuite
        }

        fun build() =
            Policy(
                    certificationSignatureHashAlgorithmPolicy,
                    revocationSignatureHashAlgorithmPolicy,
                    dataSignatureHashAlgorithmPolicy,
                    messageEncryptionMechanismPolicy,
                    messageDecryptionMechanismPolicy,
                    compressionAlgorithmPolicy,
                    publicKeyAlgorithmPolicy,
                    keyProtectionSettings,
                    notationRegistry,
                    keyGenerationAlgorithmSuite)
                .apply { enableKeyParameterValidation = origin.enableKeyParameterValidation }
    }

    abstract class FeaturePolicy {
        fun isAcceptable(feature: Byte): Boolean =
            Feature.fromId(feature)?.let { isAcceptable(it) } ?: false

        abstract fun isAcceptable(feature: Feature): Boolean

        companion object {
            @JvmStatic
            fun defaultFeaturePolicy(): FeaturePolicy {
                return whiteList(
                    listOf(Feature.MODIFICATION_DETECTION, Feature.MODIFICATION_DETECTION_2))
            }

            @JvmStatic
            fun whiteList(whitelistedFeatures: List<Feature>): FeaturePolicy {
                return object : FeaturePolicy() {
                    override fun isAcceptable(feature: Feature): Boolean {
                        return whitelistedFeatures.contains(feature)
                    }
                }
            }
        }
    }

    companion object {
        fun wildcardPolicy(): Policy =
            Policy(
                HashAlgorithmPolicy(HashAlgorithm.SHA512, HashAlgorithm.entries),
                HashAlgorithmPolicy(HashAlgorithm.SHA512, HashAlgorithm.entries),
                HashAlgorithmPolicy(HashAlgorithm.SHA512, HashAlgorithm.entries),
                object :
                    MessageEncryptionMechanismPolicy(
                        SymmetricKeyAlgorithmPolicy(
                            SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.entries),
                        MessageEncryptionMechanism.integrityProtected(
                            SymmetricKeyAlgorithm.AES_256.algorithmId)) {
                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        return true
                    }
                },
                object :
                    MessageEncryptionMechanismPolicy(
                        SymmetricKeyAlgorithmPolicy(
                            SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.entries),
                        MessageEncryptionMechanism.integrityProtected(
                            SymmetricKeyAlgorithm.AES_256.algorithmId)) {
                    override fun isAcceptable(
                        encryptionMechanism: MessageEncryptionMechanism
                    ): Boolean {
                        return true
                    }
                },
                CompressionAlgorithmPolicy.anyCompressionAlgorithmPolicy(),
                PublicKeyAlgorithmPolicy(PublicKeyAlgorithm.entries.associateWith { 0 }.toMap()),
                KeyRingProtectionSettings.secureDefaultSettings(),
                NotationRegistry(setOf()),
                AlgorithmSuite.defaultAlgorithmSuite)
    }
}
