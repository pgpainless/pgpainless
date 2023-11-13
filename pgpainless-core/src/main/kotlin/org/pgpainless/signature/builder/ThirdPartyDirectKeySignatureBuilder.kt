// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.CertificationSubpackets

/**
 * [AbstractSignatureBuilder] subclass devoted to generating direct-key signatures over primary keys
 * of third-party certificates. Such signatures are also sometimes referred to as "delegations",
 * i.e. in the context of the Web-of-Trust.
 */
class ThirdPartyDirectKeySignatureBuilder :
    AbstractSignatureBuilder<ThirdPartyDirectKeySignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() = Predicate<SignatureType> { it == SignatureType.DIRECT_KEY }

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(SignatureType.DIRECT_KEY, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature
    ) : super(signingKey, protector, archetypeSignature)

    val hashedSubpackets: CertificationSubpackets = _hashedSubpackets
    val unhashedSubpackets: CertificationSubpackets = _unhashedSubpackets

    fun applyCallback(callback: CertificationSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    @Throws(PGPException::class)
    fun build(certificate: PGPPublicKeyRing): PGPSignature = build(certificate.publicKey)

    @Throws(PGPException::class)
    fun build(certifiedKey: PGPPublicKey): PGPSignature =
        buildAndInitSignatureGenerator().generateCertification(certifiedKey)
}
