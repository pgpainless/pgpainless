// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpackets

/**
 * [AbstractSignatureBuilder] devoted to all types of self-certifications. Self-certifications are
 * certifications calculated by a primary key over its own user-ids.
 */
class SelfSignatureBuilder : AbstractSignatureBuilder<SelfSignatureBuilder> {
    override val signatureTypePredicate: Predicate<SignatureType>
        get() =
            Predicate<SignatureType> {
                it in
                    listOf(
                        SignatureType.GENERIC_CERTIFICATION,
                        SignatureType.NO_CERTIFICATION,
                        SignatureType.CASUAL_CERTIFICATION,
                        SignatureType.POSITIVE_CERTIFICATION)
            }

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(SignatureType.GENERIC_CERTIFICATION, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        signatureType: SignatureType,
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(signatureType, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        primaryKey: PGPSecretKey,
        primaryKeyProtector: SecretKeyRingProtector,
        oldCertification: PGPSignature
    ) : super(primaryKey, primaryKeyProtector, oldCertification)

    @Throws(PGPException::class)
    constructor(
        primaryKey: PGPKeyPair,
        oldCertification: PGPSignature
    ) : this(primaryKey.privateKey, primaryKey.publicKey, oldCertification)

    @Throws(PGPException::class)
    constructor(
        privatePrimaryKey: PGPPrivateKey,
        publicPrimaryKey: PGPPublicKey,
        oldCertification: PGPSignature
    ) : super(privatePrimaryKey, publicPrimaryKey, oldCertification)

    @Throws(PGPException::class)
    constructor(
        primaryKey: PGPKeyPair,
        signatureType: SignatureType = SignatureType.POSITIVE_CERTIFICATION,
        hashAlgorithm: HashAlgorithm
    ) : this(primaryKey.privateKey, primaryKey.publicKey, signatureType, hashAlgorithm)

    @Throws(PGPException::class)
    constructor(
        privatePrimaryKey: PGPPrivateKey,
        publicPrimaryKey: PGPPublicKey,
        signatureType: SignatureType = SignatureType.POSITIVE_CERTIFICATION,
        hashAlgorithm: HashAlgorithm,
    ) : super(
        privatePrimaryKey,
        publicPrimaryKey,
        hashAlgorithm,
        signatureType,
        SignatureSubpackets.createHashedSubpackets(publicPrimaryKey),
        SignatureSubpackets.createEmptySubpackets())

    val hashedSubpackets: SelfSignatureSubpackets = _hashedSubpackets
    val unhashedSubpackets: SelfSignatureSubpackets = _unhashedSubpackets

    fun applyCallback(callback: SelfSignatureSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    @Throws(PGPException::class)
    fun build(userId: CharSequence): PGPSignature =
        buildAndInitSignatureGenerator().generateCertification(userId.toString(), publicSigningKey)

    @Throws(PGPException::class)
    fun build(userAttributes: PGPUserAttributeSubpacketVector): PGPSignature =
        buildAndInitSignatureGenerator().generateCertification(userAttributes, publicSigningKey)
}
