// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentSignature
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.CertificationSubpackets

/**
 * Certification signature builder used to certify other users keys. A third-party certification is
 * calculated by the primary key of the issuer certificate, over a user-id on a third-party
 * certificate.
 */
class ThirdPartyCertificationSignatureBuilder :
    AbstractSignatureBuilder<ThirdPartyCertificationSignatureBuilder> {
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

    /**
     * Create a new certification signature builder. This constructor uses
     * [SignatureType.GENERIC_CERTIFICATION] as signature type.
     *
     * @param signingKey our own certification key
     * @param protector protector to unlock the certification key
     * @throws WrongPassphraseException in case of a wrong passphrase
     */
    @Throws(PGPException::class)
    constructor(
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        api: PGPainless
    ) : super(SignatureType.GENERIC_CERTIFICATION, signingKey, protector, api)

    /**
     * Create a new certification signature builder.
     *
     * @param signatureType type of certification
     * @param signingKey our own certification key
     * @param protector protector to unlock the certification key
     * @throws WrongPassphraseException in case of a wrong passphrase
     */
    @Throws(PGPException::class)
    constructor(
        signatureType: SignatureType,
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        api: PGPainless
    ) : super(signatureType, signingKey, protector, api)

    /**
     * Create a new certification signature builder.
     *
     * @param signingKey our own certification key
     * @param protector protector to unlock the certification key
     * @param archetypeSignature signature to use as a template for the new signature
     * @throws WrongPassphraseException in case of a wrong passphrase
     */
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

    fun build(certificate: OpenPGPCertificate, userId: CharSequence): OpenPGPSignature =
        buildAndInitSignatureGenerator()
            .generateCertification(userId.toString(), certificate.primaryKey.pgpPublicKey)
            .let {
                OpenPGPComponentSignature(
                    it,
                    signingKey.publicKey,
                    OpenPGPCertificate.OpenPGPUserId(userId.toString(), certificate.primaryKey))
            }

    /**
     * Create a certification signature for the given user-id and the given third-party certificate.
     *
     * @param certificate third-party certificate
     * @param userId user-id to certify
     * @return signature
     * @throws PGPException if the signature generator cannot be initialized
     */
    @Throws(PGPException::class)
    @Deprecated("Pass in an OpenPGPCertificate instead of a PGPPublicKeyRing.")
    fun build(certificate: PGPPublicKeyRing, userId: CharSequence): PGPSignature =
        build(api.toCertificate(certificate), userId).signature

    fun build(
        certificate: OpenPGPCertificate,
        userAttribute: PGPUserAttributeSubpacketVector
    ): OpenPGPSignature =
        OpenPGPComponentSignature(
            buildAndInitSignatureGenerator()
                .generateCertification(userAttribute, certificate.primaryKey.pgpPublicKey),
            signingKey.publicKey,
            OpenPGPCertificate.OpenPGPUserAttribute(userAttribute, certificate.primaryKey))

    /**
     * Create a certification signature for the given user attribute and the given third-party
     * certificate.
     *
     * @param certificate third-party certificate
     * @param userAttribute user-attributes to certify
     * @return signature
     * @throws PGPException if the signature generator cannot be initialized
     */
    @Throws(PGPException::class)
    @Deprecated("Pass in an OpenPGPCertificate instead of a PGPPublicKeyRing.")
    fun build(
        certificate: PGPPublicKeyRing,
        userAttribute: PGPUserAttributeSubpacketVector
    ): PGPSignature = build(api.toCertificate(certificate), userAttribute).signature
}
