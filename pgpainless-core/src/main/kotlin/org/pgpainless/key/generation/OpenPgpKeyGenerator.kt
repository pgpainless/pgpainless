package org.pgpainless.key.generation

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Date
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.policy.Policy
import org.pgpainless.provider.ProviderFactory
import org.pgpainless.signature.builder.DirectKeySelfSignatureBuilder
import org.pgpainless.signature.builder.SelfSignatureBuilder
import org.pgpainless.signature.builder.SubkeyBindingSignatureBuilder
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

/**
 * Build a version 4 OpenPGP secret key.
 *
 * @param policy policy to ensure algorithm compliance and to determine default algorithms
 * @param creationTime creation time for the secret key
 */
fun buildV4(
    policy: Policy = PGPainless.getPolicy(),
    creationTime: Date = Date(),
    preferences: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
): OpinionatedDefinePrimaryKey.V4 {
    return OpinionatedDefinePrimaryKey.V4(policy, creationTime, preferences)
}

/**
 * Build a version 6 OpenPGP secret key.
 *
 * @param policy policy to ensure algorithm compliance and to determine default algorithms
 * @param creationTime creation time for the secret key
 */
fun buildV6(
    policy: Policy = PGPainless.getPolicy(),
    creationTime: Date = Date(),
    preferences: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
): OpinionatedDefinePrimaryKey.V6 {
    return OpinionatedDefinePrimaryKey.V6(policy, creationTime, preferences)
}

/**
 * Builder that allows the user to define the primary key of the OpenPGP key.
 *
 * @param policy algorithm policy
 * @param creationTime default value for the creation time of the primary key.
 */
abstract class DefinePrimaryKey<B : DefineSubkeys<B>>(
    val policy: Policy,
    val creationTime: Date,
) {

    /**
     * Define the primary key of the OpenPGP key.
     *
     * @param type primary key type
     * @param creationTime creation time of the primary key. Defaults to the [DefinePrimaryKey]'s
     *   [creationTime].
     * @param applyToPrimaryKey function that gets applied to the primary key. Is used to add
     *   binding signatures, UserIDs and user-attributes on the primary key.
     * @return next step key builder
     */
    abstract fun setPrimaryKey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)? = null // default: do nothing
    ): B

    abstract fun preferencesSubpackets(): SelfSignatureSubpackets.Callback
}

/**
 * Opinionated implementation of [DefinePrimaryKey]. Contrary to an unopinionated implementation, an
 * opinionated [DefinePrimaryKey] will sanity check user-provided parameters and make sure, required
 * signatures are placed on the key etc.
 *
 * @param policy policy to sanity check algorithms, key strengths etc. and to determine fallback
 *   algorithms with
 * @param creationTime creation time of the primary key
 * @param unopinionated unopinionated implementation
 * @param B opinionated builder type
 * @param U unopinionated builder type
 */
abstract class OpinionatedDefinePrimaryKey<
    B : OpinionatedDefineSubkeys, U : UnopinionatedDefineSubkeys>(
    policy: Policy,
    creationTime: Date,
    val preferences: AlgorithmSuite,
    protected val unopinionated: UnopinionatedDefinePrimaryKey<U>
) : DefinePrimaryKey<OpinionatedDefineSubkeys>(policy, creationTime) {

    /**
     * Turn this builder into an unopinionated one by returning the underlying unopinionated
     * implementation.
     *
     * @return unopinionated implementation
     */
    abstract fun unopinionated(): UnopinionatedDefinePrimaryKey<U>

    override fun preferencesSubpackets(): SelfSignatureSubpackets.Callback =
        SelfSignatureSubpackets.applyHashed {
            setSignatureCreationTime(creationTime)
            setPreferredHashAlgorithms(preferences.hashAlgorithms)
            setPreferredSymmetricKeyAlgorithms(preferences.symmetricKeyAlgorithms)
            setPreferredCompressionAlgorithms(preferences.compressionAlgorithms)
            setFeatures(preferences.features)
        }

    fun setCertificationKey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)? = { keyPair }
    ): B {
        return setPrimaryKey(type, creationTime) {
            addDirectKeySignature(
                preferencesSubpackets()
                    .then(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) }))
            then(applyToPrimaryKey)
        }
            as B
    }

    /**
     * Implementation of an [OpinionatedDefinePrimaryKey] for OpenPGP v4 keys.
     *
     * @param policy policy for algorithm compliance and fallbacks
     * @param creationTime creation time of the primary key
     */
    class V4(policy: Policy, creationTime: Date, preferences: AlgorithmSuite) :
        OpinionatedDefinePrimaryKey<OpinionatedDefineSubkeys.V4, UnopinionatedDefineSubkeys.V4>(
            policy,
            creationTime,
            preferences,
            UnopinionatedDefinePrimaryKey.V4(policy, creationTime)) {

        override fun unopinionated(): UnopinionatedDefinePrimaryKey.V4 =
            unopinionated as UnopinionatedDefinePrimaryKey.V4

        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
        ): OpinionatedDefineSubkeys.V4 {

            val applier = applyToPrimaryKey ?: { addDirectKeySignature(preferencesSubpackets()) }

            val unopinionatedSubkeys = unopinionated().setPrimaryKey(type, creationTime, applier)
            return OpinionatedDefineSubkeys.V4(
                unopinionatedSubkeys.primaryKey, policy, creationTime, unopinionatedSubkeys)
        }
    }

    /**
     * Implementation of an [OpinionatedDefinePrimaryKey] for OpenPGP v6 keys.
     *
     * @param policy policy for algorithm compliance and fallbacks
     * @param creationTime creation time of the primary key
     */
    class V6(policy: Policy, creationTime: Date, preferences: AlgorithmSuite) :
        OpinionatedDefinePrimaryKey<OpinionatedDefineSubkeys.V6, UnopinionatedDefineSubkeys.V6>(
            policy,
            creationTime,
            preferences,
            UnopinionatedDefinePrimaryKey.V6(policy, creationTime)) {

        override fun unopinionated(): UnopinionatedDefinePrimaryKey.V6 =
            unopinionated as UnopinionatedDefinePrimaryKey.V6

        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
        ): OpinionatedDefineSubkeys.V6 {
            val applier = applyToPrimaryKey ?: { addDirectKeySignature(preferencesSubpackets()) }
            return OpinionatedDefineSubkeys.V6(
                policy,
                creationTime,
                unopinionated.setPrimaryKey(type, creationTime, applier)
                    as UnopinionatedDefineSubkeys.V6)
        }
    }
}

/**
 * Unopinionated implementation of [DefinePrimaryKey]. An unopinionated [DefinePrimaryKey] will not
 * perform any sanity checks on user-provided algorithms.
 *
 * @param creationTime creation time of the primary key
 * @param U unopinionated builder type
 */
abstract class UnopinionatedDefinePrimaryKey<U : UnopinionatedDefineSubkeys>(
    policy: Policy,
    creationTime: Date,
) : DefinePrimaryKey<UnopinionatedDefineSubkeys>(policy, creationTime) {

    override fun preferencesSubpackets(): SelfSignatureSubpackets.Callback =
        SelfSignatureSubpackets.nop()

    /**
     * Implementation of an [UnopinionatedDefinePrimaryKey] for OpenPGP v4 keys.
     *
     * @param creationTime creation time of the primary key
     */
    class V4(policy: Policy, creationTime: Date) :
        UnopinionatedDefinePrimaryKey<UnopinionatedDefineSubkeys.V4>(policy, creationTime) {

        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
        ): UnopinionatedDefineSubkeys.V4 {
            var primaryKey = OpenPgpKeyPairGenerator.V4().generatePrimaryKey(type, creationTime)
            if (applyToPrimaryKey != null) {
                primaryKey = ApplyToPrimaryKey.V4(primaryKey, this).applyToPrimaryKey()
            }
            return UnopinionatedDefineSubkeys.V4(primaryKey, policy, creationTime)
        }
    }

    /**
     * Implementation of an [UnopinionatedDefinePrimaryKey] for OpenPGP v6 keys.
     *
     * @param creationTime creation time of the primary key
     */
    class V6(policy: Policy, creationTime: Date) :
        UnopinionatedDefinePrimaryKey<UnopinionatedDefineSubkeys.V6>(policy, creationTime) {
        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
        ): UnopinionatedDefineSubkeys.V6 {
            return UnopinionatedDefineSubkeys.V6(policy, creationTime)
        }
    }
}

/** Interface for key builder that can */
abstract class DefineSubkeys<B : DefineSubkeys<B>>(val policy: Policy, val creationTime: Date) {

    /**
     * Add a subkey to the OpenPGP key.
     *
     * @param type subkey type
     * @param creationTime creation time of the subkey
     * @param function function to apply to the subkey. Used to add binding signatures.
     * @return this
     */
    abstract fun addSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        function: (ApplyToSubkey.() -> PGPKeyPair)? = null
    ): B

    /**
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing].
     *
     * @return finished [PGPSecretKeyRing]
     */
    abstract fun build(): PGPSecretKeyRing
}

abstract class OpinionatedDefineSubkeys(policy: Policy, creationTime: Date) :
    DefineSubkeys<OpinionatedDefineSubkeys>(policy, creationTime) {

    abstract val unopinionated: UnopinionatedDefineSubkeys

    override fun build(): PGPSecretKeyRing = unopinionated.build()

    class V4(
        primaryKey: PGPKeyPair,
        policy: Policy,
        creationTime: Date,
        override val unopinionated: UnopinionatedDefineSubkeys.V4 =
            UnopinionatedDefineSubkeys.V4(primaryKey, policy, creationTime)
    ) : OpinionatedDefineSubkeys(policy, creationTime) {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)?
        ): V4 = apply { unopinionated.addSubkey(type, creationTime, applyToSubkey) }

        fun addSigningSubkey(
            type: KeyType,
            creationTime: Date = this.creationTime,
            applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)? = {
                addBindingSignature(
                    SelfSignatureSubpackets.applyHashed {
                        setSignatureCreationTime(creationTime)
                        setKeyFlags(KeyFlag.SIGN_DATA)
                    })
            }
        ) = addSubkey(type, creationTime, applyToSubkey)

        fun addEncryptionSubkey(
            type: KeyType,
            creationTime: Date = this.creationTime,
            applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)? = {
                addBindingSignature(
                    SelfSignatureSubpackets.applyHashed {
                        setSignatureCreationTime(creationTime)
                        setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                    })
            }
        ) = addSubkey(type, creationTime, applyToSubkey)
    }

    class V6(
        policy: Policy,
        creationTime: Date,
        override val unopinionated: UnopinionatedDefineSubkeys.V6 =
            UnopinionatedDefineSubkeys.V6(policy, creationTime)
    ) : OpinionatedDefineSubkeys(policy, creationTime) {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            function: (ApplyToSubkey.() -> PGPKeyPair)?
        ): V6 = apply { unopinionated.addSubkey(type, creationTime, function) }
    }
}

abstract class UnopinionatedDefineSubkeys(policy: Policy, creationTime: Date) :
    DefineSubkeys<UnopinionatedDefineSubkeys>(policy, creationTime) {

    class V4(val primaryKey: PGPKeyPair, policy: Policy, creationTime: Date) :
        UnopinionatedDefineSubkeys(policy, creationTime) {

        val subkeys: MutableList<PGPKeyPair> = mutableListOf()

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)?
        ): V4 = apply {
            val subkey = OpenPgpKeyPairGenerator.V4().generateSubkey(type, creationTime)
            subkeys.add(
                if (applyToSubkey == null) {
                    subkey
                } else {
                    ApplyToSubkey.V4(primaryKey, subkey, this).applyToSubkey()
                })
        }

        override fun build(): PGPSecretKeyRing {
            val primary =
                PGPSecretKey(
                    primaryKey.privateKey,
                    primaryKey.publicKey,
                    ImplementationFactory.getInstance().v4FingerprintCalculator,
                    true,
                    null)
            return PGPSecretKeyRing(
                buildList {
                    add(primary)
                    subkeys.forEach {
                        add(
                            PGPSecretKey(
                                it.privateKey,
                                it.publicKey,
                                ImplementationFactory.getInstance().v4FingerprintCalculator,
                                false,
                                null))
                    }
                })
        }
    }

    class V6(policy: Policy, creationTime: Date) :
        UnopinionatedDefineSubkeys(policy, creationTime) {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            function: (ApplyToSubkey.() -> PGPKeyPair)?
        ): V6 =
            apply {
                // Add Key
            }

        override fun build(): PGPSecretKeyRing {
            TODO("Not yet implemented")
        }
    }
}

/** Function that can be applied to the primary key. */
abstract class ApplyToPrimaryKey(var keyPair: PGPKeyPair, val builder: DefinePrimaryKey<*>) {

    /**
     * Add a UserID to the primary key.
     *
     * @param userId UserID to be bound to the primary key
     * @param subpacketsCallback callback to modify the binding signatures subpackets
     */
    abstract fun addUserId(
        userId: CharSequence,
        subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
        certificationType: CertificationType = CertificationType.POSITIVE,
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = builder.creationTime
    ): PGPKeyPair

    /**
     * Add a DirectKeySignature to the primary key. Such a signature usually carries information
     * that applies to the whole OpenPGP key, such as algorithm preferences etc.
     */
    abstract fun addDirectKeySignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback = builder.preferencesSubpackets(),
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = builder.creationTime
    ): PGPKeyPair

    abstract fun then(other: (ApplyToPrimaryKey.() -> PGPKeyPair)?): PGPKeyPair

    class V4(keyPair: PGPKeyPair, builder: DefinePrimaryKey<*>) :
        ApplyToPrimaryKey(keyPair, builder) {

        override fun addUserId(
            userId: CharSequence,
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            certificationType: CertificationType,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        ): PGPKeyPair {
            val sig =
                buildCertificationFor(
                    keyPair,
                    userId,
                    certificationType,
                    bindingTime,
                    hashAlgorithm,
                    subpacketsCallback)

            keyPair =
                PGPKeyPair(
                    PGPPublicKey.addCertification(keyPair.publicKey, userId.toString(), sig),
                    keyPair.privateKey)
            return keyPair
        }

        override fun addDirectKeySignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        ): PGPKeyPair {
            val sig =
                buildDirectKeySignature(
                    keyPair,
                    hashAlgorithm,
                    subpacketsCallback.then(
                        SelfSignatureSubpackets.applyHashed {
                            setSignatureCreationTime(bindingTime)
                        }))
            keyPair =
                PGPKeyPair(
                    PGPPublicKey.addCertification(keyPair.publicKey, sig), keyPair.privateKey)
            return keyPair
        }

        override fun then(other: (ApplyToPrimaryKey.() -> PGPKeyPair)?): PGPKeyPair {
            if (other != null) {
                keyPair = V4(keyPair, builder).other()
            }
            return keyPair
        }

        fun buildCertificationFor(
            pair: PGPKeyPair,
            userId: CharSequence,
            certificationType: CertificationType,
            bindingTime: Date,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                SelfSignatureBuilder(
                    pair.privateKey, pair.publicKey, certificationType.signatureType, hashAlgorithm)
            builder.hashedSubpackets.apply { setSignatureCreationTime(bindingTime) }
            builder.applyCallback(subpacketsCallback)
            return builder.build(userId)
        }

        fun buildCertificationFor(
            pair: PGPKeyPair,
            userAttribute: PGPUserAttributeSubpacketVector,
            certificationType: CertificationType,
            bindingTime: Date,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                SelfSignatureBuilder(
                    pair.privateKey, pair.publicKey, certificationType.signatureType, hashAlgorithm)
            builder.hashedSubpackets.apply { setSignatureCreationTime(bindingTime) }
            builder.applyCallback(subpacketsCallback)
            return builder.build(userAttribute)
        }

        fun buildDirectKeySignature(
            pair: PGPKeyPair,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                DirectKeySelfSignatureBuilder(pair.privateKey, pair.publicKey, hashAlgorithm)

            builder.applyCallback(subpacketsCallback)

            return builder.build()
        }
    }
}

/** Function that can be applied to subkeys. */
abstract class ApplyToSubkey(
    val primaryKey: PGPKeyPair,
    val subkey: PGPKeyPair,
    val builder: DefineSubkeys<*>
) {

    /**
     * Add a binding signature to the subkey.
     *
     * @param subpacketsCallback callback to modify the binding signatures subpackets
     */
    abstract fun addBindingSignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = subkey.publicKey.creationTime
    ): PGPKeyPair

    class V4(primaryKey: PGPKeyPair, subkey: PGPKeyPair, builder: DefineSubkeys<*>) :
        ApplyToSubkey(primaryKey, subkey, builder) {

        override fun addBindingSignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        ): PGPKeyPair {
            val sig =
                buildBindingSignature(
                    primaryKey, subkey, hashAlgorithm, bindingTime, subpacketsCallback)

            return PGPKeyPair(
                PGPPublicKey.addCertification(subkey.publicKey, sig), subkey.privateKey)
        }

        fun buildBindingSignature(
            primaryKey: PGPKeyPair,
            subkey: PGPKeyPair,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            return SubkeyBindingSignatureBuilder(
                    primaryKey.privateKey, primaryKey.publicKey, hashAlgorithm)
                .applyCallback(
                    subpacketsCallback.then(
                        SelfSignatureSubpackets.applyHashed {
                            setSignatureCreationTime(bindingTime)
                        }))
                .build(subkey.publicKey)
        }
    }
}

internal fun generateKeyPair(type: KeyType): KeyPair =
    KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
        .also { it.initialize(type.algorithmSpec) }
        .generateKeyPair()

class OpenPgpKeyTemplates {

    companion object {
        @JvmStatic fun v4() = V4()
    }

    class V4 {

        fun ed25519Curve25519(
            vararg userId: CharSequence,
            creationTime: Date = Date()
        ): PGPSecretKeyRing =
            buildV4(creationTime = creationTime)
                // .setCertificationKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    userId.forEach { addUserId(it) }
                    addDirectKeySignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) })
                    keyPair
                }
                .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.SIGN_DATA) })
                }
                .addSubkey(KeyType.XDH(XDHSpec._X25519)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed {
                            setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                        })
                }
                .build()

        fun composedRsa(
            vararg userId: CharSequence,
            creationTime: Date = Date(),
            length: RsaLength = RsaLength._4096
        ): PGPSecretKeyRing =
            buildV4(creationTime = creationTime)
                .setPrimaryKey(KeyType.RSA(length)) {
                    userId.forEach { addUserId(it) }
                    addDirectKeySignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) })
                    keyPair
                }
                .addSubkey(KeyType.RSA(length)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.SIGN_DATA) })
                }
                .addSubkey(KeyType.RSA(length)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed {
                            setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                        })
                }
                .build()

        fun singleRsa(
            vararg userId: CharSequence,
            creationTime: Date = Date(),
            length: RsaLength = RsaLength._4096
        ): PGPSecretKeyRing =
            buildV4(creationTime = creationTime)
                .setPrimaryKey(KeyType.RSA(length)) {
                    userId.forEach { addUserId(it) }
                    addDirectKeySignature(
                        SelfSignatureSubpackets.applyHashed {
                            setKeyFlags(
                                KeyFlag.CERTIFY_OTHER,
                                KeyFlag.SIGN_DATA,
                                KeyFlag.ENCRYPT_COMMS,
                                KeyFlag.ENCRYPT_STORAGE)
                        })
                    keyPair
                }
                .build()
    }
}
