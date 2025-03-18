// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentSignature
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPSignature
import org.pgpainless.PGPainless
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
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        api: PGPainless
    ) : super(SignatureType.DIRECT_KEY, signingKey, protector, api)

    @Throws(PGPException::class)
    constructor(
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature,
        api: PGPainless
    ) : super(signingKey, protector, archetypeSignature, api)

    val hashedSubpackets: CertificationSubpackets = _hashedSubpackets
    val unhashedSubpackets: CertificationSubpackets = _unhashedSubpackets

    fun applyCallback(callback: CertificationSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    fun build(certificate: OpenPGPCertificate): OpenPGPSignature = build(certificate.primaryKey)

    fun build(componentKey: OpenPGPComponentKey): OpenPGPSignature =
        OpenPGPComponentSignature(
            buildAndInitSignatureGenerator().generateCertification(componentKey.pgpPublicKey),
            signingKey.publicKey,
            componentKey)

    @Throws(PGPException::class)
    @Deprecated("Pass in an OpenPGPCertificate instead.")
    fun build(certificate: PGPPublicKeyRing): PGPSignature =
        build(api.toCertificate(certificate)).signature

    @Deprecated("Pass in an OpenPGPComponentKey instead.")
    @Throws(PGPException::class)
    fun build(certifiedKey: PGPPublicKey): PGPSignature =
        buildAndInitSignatureGenerator().generateCertification(certifiedKey)
}
