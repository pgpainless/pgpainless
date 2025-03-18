// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil
import org.pgpainless.signature.subpackets.SignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper

abstract class AbstractSignatureBuilder<B : AbstractSignatureBuilder<B>>(
    protected val signingKey: OpenPGPKey.OpenPGPPrivateKey,
    protected var _hashAlgorithm: HashAlgorithm,
    protected var _signatureType: SignatureType,
    protected val _hashedSubpackets: SignatureSubpackets,
    protected val _unhashedSubpackets: SignatureSubpackets,
    protected val api: PGPainless
) {

    protected abstract val signatureTypePredicate: Predicate<SignatureType>

    init {
        require(signatureTypePredicate.test(_signatureType)) {
            "Invalid signature type: $_signatureType"
        }
    }

    @Throws(PGPException::class)
    protected constructor(
        signatureType: SignatureType,
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        hashAlgorithm: HashAlgorithm,
        hashedSubpackets: SignatureSubpackets,
        unhashedSubpackets: SignatureSubpackets,
        api: PGPainless
    ) : this(
        UnlockSecretKey.unlockSecretKey(signingKey, protector),
        hashAlgorithm,
        signatureType,
        hashedSubpackets,
        unhashedSubpackets,
        api)

    @Throws(PGPException::class)
    constructor(
        signatureType: SignatureType,
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        api: PGPainless
    ) : this(
        signatureType,
        signingKey,
        protector,
        negotiateHashAlgorithm(signingKey, api),
        SignatureSubpackets.createHashedSubpackets(signingKey.pgpSecretKey.publicKey),
        SignatureSubpackets.createEmptySubpackets(),
        api)

    @Throws(PGPException::class)
    constructor(
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature,
        api: PGPainless
    ) : this(
        SignatureType.requireFromCode(archetypeSignature.signatureType),
        signingKey,
        protector,
        negotiateHashAlgorithm(signingKey, api),
        SignatureSubpackets.refreshHashedSubpackets(
            signingKey.publicKey.pgpPublicKey, archetypeSignature),
        SignatureSubpackets.refreshUnhashedSubpackets(archetypeSignature),
        api)

    val hashAlgorithm = _hashAlgorithm

    fun overrideHashAlgorithm(hashAlgorithm: HashAlgorithm) =
        apply { _hashAlgorithm = hashAlgorithm } as B

    /**
     * Set the builders [SignatureType]. Note that only those types who are valid for the concrete
     * subclass of this [AbstractSignatureBuilder] are allowed. Invalid choices result in an
     * [IllegalArgumentException] to be thrown.
     *
     * @param type signature type
     * @return builder
     */
    fun setSignatureType(type: SignatureType) =
        apply {
            require(signatureTypePredicate.test(type)) { "Invalid signature type: $type" }
            _signatureType = type
        }
            as B

    /**
     * Build an instance of [PGPSignatureGenerator] initialized with the signing key and with hashed
     * and unhashed subpackets.
     *
     * @return pgp signature generator
     * @throws PGPException if the signature generator cannot be initialized
     */
    @Throws(PGPException::class)
    protected fun buildAndInitSignatureGenerator(): PGPSignatureGenerator =
        PGPSignatureGenerator(
                api.implementation.pgpContentSignerBuilder(
                    signingKey.keyPair.publicKey.algorithm, hashAlgorithm.algorithmId),
                signingKey.keyPair.publicKey)
            .apply {
                setUnhashedSubpackets(SignatureSubpacketsHelper.toVector(_unhashedSubpackets))
                setHashedSubpackets(SignatureSubpacketsHelper.toVector(_hashedSubpackets))
                init(_signatureType.code, signingKey.keyPair.privateKey)
            }

    companion object {

        /**
         * Negotiate a [HashAlgorithm] to be used when creating the signature.
         *
         * @param publicKey signing public key
         * @return hash algorithm
         */
        @JvmStatic
        fun negotiateHashAlgorithm(publicKey: PGPPublicKey, api: PGPainless): HashAlgorithm =
            HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(api.algorithmPolicy)
                .negotiateHashAlgorithm(
                    OpenPgpKeyAttributeUtil.getOrGuessPreferredHashAlgorithms(publicKey))

        @JvmStatic
        fun negotiateHashAlgorithm(key: OpenPGPComponentKey, api: PGPainless): HashAlgorithm =
            negotiateHashAlgorithm(key.pgpPublicKey, api)
    }
}
