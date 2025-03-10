// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

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
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(SignatureType.GENERIC_CERTIFICATION, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        signatureType: SignatureType,
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(signatureType, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        primaryKey: OpenPGPKey.OpenPGPSecretKey,
        primaryKeyProtector: SecretKeyRingProtector,
        oldCertification: PGPSignature
    ) : super(primaryKey, primaryKeyProtector, oldCertification)

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
        buildAndInitSignatureGenerator()
            .generateCertification(userId.toString(), signingKey.publicKey.pgpPublicKey)

    @Throws(PGPException::class)
    fun build(userAttributes: PGPUserAttributeSubpacketVector): PGPSignature =
        buildAndInitSignatureGenerator()
            .generateCertification(userAttributes, signingKey.publicKey.pgpPublicKey)
}
