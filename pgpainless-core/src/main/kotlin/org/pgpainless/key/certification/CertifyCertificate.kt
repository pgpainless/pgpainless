// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.certification

import java.util.*
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.Trustworthiness
import org.pgpainless.exception.KeyException
import org.pgpainless.exception.KeyException.ExpiredKeyException
import org.pgpainless.exception.KeyException.MissingSecretKeyException
import org.pgpainless.exception.KeyException.RevokedKeyException
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.signature.builder.ThirdPartyCertificationSignatureBuilder
import org.pgpainless.signature.builder.ThirdPartyDirectKeySignatureBuilder
import org.pgpainless.signature.subpackets.CertificationSubpackets

/**
 * API for creating certifications and delegations (Signatures) on keys. This API can be used to
 * sign another persons OpenPGP key.
 *
 * A certification over a user-id is thereby used to attest, that the user believes that the user-id
 * really belongs to the owner of the certificate. A delegation over a key can be used to delegate
 * trust by marking the certificate as a trusted introducer.
 */
class CertifyCertificate {

    /**
     * Create a certification over a User-Id. By default, this method will use
     * [CertificationType.GENERIC] to create the signature.
     *
     * @param userId user-id to certify
     * @param certificate certificate
     * @return API
     */
    @JvmOverloads
    fun userIdOnCertificate(
        userId: CharSequence,
        certificate: OpenPGPCertificate,
        certificationType: CertificationType = CertificationType.GENERIC
    ): CertificationOnUserId = CertificationOnUserId(userId, certificate, certificationType)

    /**
     * Create a certification over a User-Id. By default, this method will use
     * [CertificationType.GENERIC] to create the signature.
     *
     * @param userId user-id to certify
     * @param certificate certificate
     * @return API
     */
    @Deprecated("Pass in an OpenPGPCertificate instead of PGPPublicKeyRing.")
    fun userIdOnCertificate(userId: String, certificate: PGPPublicKeyRing): CertificationOnUserId =
        userIdOnCertificate(userId, certificate, CertificationType.GENERIC)

    /**
     * Create a certification of the given [CertificationType] over a User-Id.
     *
     * @param userId user-id to certify
     * @param certificate certificate
     * @param certificationType type of signature
     * @return API
     */
    @Deprecated("Pass in an OpenPGPCertificate instead of PGPPublicKeyRing.")
    fun userIdOnCertificate(
        userId: String,
        certificate: PGPPublicKeyRing,
        certificationType: CertificationType
    ) = CertificationOnUserId(userId, certificate, certificationType)

    /**
     * Create a delegation (direct key signature) over a certificate. This can be used to mark a
     * certificate as a trusted introducer (see [certificate] method with [Trustworthiness]
     * argument).
     *
     * @param certificate certificate
     * @return API
     */
    @JvmOverloads
    fun certificate(certificate: OpenPGPCertificate, trustworthiness: Trustworthiness? = null) =
        DelegationOnCertificate(certificate, trustworthiness)

    /**
     * Create a delegation (direct key signature) over a certificate. This can be used to mark a
     * certificate as a trusted introducer (see [certificate] method with [Trustworthiness]
     * argument).
     *
     * @param certificate certificate
     * @return API
     */
    @Deprecated("Pass in an OpenPGPCertificate instead of PGPPublicKeyRing.")
    fun certificate(certificate: PGPPublicKeyRing): DelegationOnCertificate =
        certificate(certificate, null)

    /**
     * Create a delegation (direct key signature) containing a
     * [org.bouncycastle.bcpg.sig.TrustSignature] packet over a certificate. This can be used to
     * mark a certificate as a trusted introducer.
     *
     * @param certificate certificate
     * @param trustworthiness trustworthiness of the certificate
     * @return API
     */
    @Deprecated("Pass in an OpenPGPCertificate instead of PGPPublicKeyRing.")
    fun certificate(certificate: PGPPublicKeyRing, trustworthiness: Trustworthiness?) =
        DelegationOnCertificate(certificate, trustworthiness)

    class CertificationOnUserId(
        val userId: CharSequence,
        val certificate: OpenPGPCertificate,
        val certificationType: CertificationType
    ) {

        @Deprecated("Use primary constructor instead.")
        constructor(
            userId: String,
            certificate: PGPPublicKeyRing,
            certificationType: CertificationType
        ) : this(userId, PGPainless.getInstance().toCertificate(certificate), certificationType)

        fun withKey(
            key: OpenPGPKey,
            protector: SecretKeyRingProtector
        ): CertificationOnUserIdWithSubpackets {
            val secretKey = getCertifyingSecretKey(key)
            val sigBuilder =
                ThirdPartyCertificationSignatureBuilder(
                    certificationType.asSignatureType(), secretKey, protector)

            return CertificationOnUserIdWithSubpackets(certificate, userId, sigBuilder)
        }

        /**
         * Create the certification using the given key.
         *
         * @param certificationKey key used to create the certification
         * @param protector protector to unlock the certification key
         * @return API
         * @throws PGPException in case of an OpenPGP related error
         */
        @Deprecated("Pass in an OpenPGPKey instead of a PGPSecretKeyRing.")
        fun withKey(
            certificationKey: PGPSecretKeyRing,
            protector: SecretKeyRingProtector
        ): CertificationOnUserIdWithSubpackets =
            withKey(PGPainless.getInstance().toKey(certificationKey), protector)
    }

    class CertificationOnUserIdWithSubpackets(
        val certificate: OpenPGPCertificate,
        val userId: CharSequence,
        val sigBuilder: ThirdPartyCertificationSignatureBuilder
    ) {

        @Deprecated("Pass in an OpenPGPCertificate instead of a PGPPublicKeyRing.")
        constructor(
            certificate: PGPPublicKeyRing,
            userId: String,
            sigBuilder: ThirdPartyCertificationSignatureBuilder
        ) : this(PGPainless.getInstance().toCertificate(certificate), userId, sigBuilder)

        /**
         * Apply the given signature subpackets and build the certification.
         *
         * @param subpacketCallback callback to modify the signatures subpackets
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        fun buildWithSubpackets(
            subpacketCallback: CertificationSubpackets.Callback
        ): CertificationResult {
            sigBuilder.applyCallback(subpacketCallback)
            return build()
        }

        /**
         * Build the certification signature.
         *
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        fun build(): CertificationResult {
            val signature = sigBuilder.build(certificate, userId)
            val certifiedCertificate =
                OpenPGPCertificate(
                    KeyRingUtils.injectCertification(
                        certificate.pgpPublicKeyRing, userId, signature.signature))

            return CertificationResult(certifiedCertificate, signature)
        }
    }

    class DelegationOnCertificate(
        val certificate: OpenPGPCertificate,
        val trustworthiness: Trustworthiness?
    ) {

        @Deprecated("Pass in an OpenPGPCertificate instead of PGPPublicKeyRing.")
        constructor(
            certificate: PGPPublicKeyRing,
            trustworthiness: Trustworthiness?
        ) : this(PGPainless.getInstance().toCertificate(certificate), trustworthiness)

        fun withKey(
            key: OpenPGPKey,
            protector: SecretKeyRingProtector
        ): DelegationOnCertificateWithSubpackets {
            val secretKey = getCertifyingSecretKey(key)
            val sigBuilder = ThirdPartyDirectKeySignatureBuilder(secretKey, protector)
            if (trustworthiness != null) {
                sigBuilder.hashedSubpackets.setTrust(
                    true, trustworthiness.depth, trustworthiness.amount)
            }
            return DelegationOnCertificateWithSubpackets(certificate, sigBuilder)
        }

        /**
         * Build the delegation using the given certification key.
         *
         * @param certificationKey key to create the certification with
         * @param protector protector to unlock the certification key
         * @return API
         * @throws PGPException in case of an OpenPGP related error
         */
        @Deprecated("Pass in an OpenPGPKey instead of PGPSecretKeyRing.")
        fun withKey(
            certificationKey: PGPSecretKeyRing,
            protector: SecretKeyRingProtector
        ): DelegationOnCertificateWithSubpackets =
            withKey(PGPainless.getInstance().toKey(certificationKey), protector)
    }

    class DelegationOnCertificateWithSubpackets(
        val certificate: OpenPGPCertificate,
        val sigBuilder: ThirdPartyDirectKeySignatureBuilder
    ) {

        @Deprecated("Pass in an OpenPGPCertificate instead of a PGPPublicKeyRing.")
        constructor(
            certificate: PGPPublicKeyRing,
            sigBuilder: ThirdPartyDirectKeySignatureBuilder
        ) : this(PGPainless.getInstance().toCertificate(certificate), sigBuilder)

        /**
         * Apply the given signature subpackets and build the delegation signature.
         *
         * @param subpacketsCallback callback to modify the signatures subpackets
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        fun buildWithSubpackets(
            subpacketsCallback: CertificationSubpackets.Callback
        ): CertificationResult {
            sigBuilder.applyCallback(subpacketsCallback)
            return build()
        }

        /**
         * Build the delegation signature.
         *
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        fun build(): CertificationResult {
            val delegatedKey = certificate.primaryKey
            val delegation = sigBuilder.build(delegatedKey)
            val delegatedCertificate =
                OpenPGPCertificate(
                    KeyRingUtils.injectCertification(
                        certificate.pgpPublicKeyRing,
                        delegatedKey.pgpPublicKey,
                        delegation.signature))
            return CertificationResult(delegatedCertificate, delegation)
        }
    }

    /**
     * Result of a certification operation.
     *
     * @param certifiedCertificate certificate which now contains the newly created signature
     * @param certification the newly created signature
     */
    data class CertificationResult(
        val certifiedCertificate: OpenPGPCertificate,
        val certification: OpenPGPSignature
    ) {
        val publicKeyRing: PGPPublicKeyRing = certifiedCertificate.pgpPublicKeyRing
        val pgpSignature: PGPSignature = certification.signature
    }

    companion object {
        @JvmStatic
        private fun getCertifyingSecretKey(
            certificationKey: OpenPGPKey
        ): OpenPGPKey.OpenPGPSecretKey {
            val now = Date()
            val info = PGPainless.inspectKeyRing(certificationKey, now)

            val fingerprint = info.fingerprint
            val certificationPubKey = info.getPublicKey(fingerprint)
            requireNotNull(certificationPubKey) { "Primary key cannot be null." }
            if (!info.isKeyValidlyBound(certificationPubKey.keyIdentifier)) {
                throw RevokedKeyException(fingerprint)
            }

            if (!info.isUsableForThirdPartyCertification) {
                throw KeyException.UnacceptableThirdPartyCertificationKeyException(fingerprint)
            }

            val expirationDate = info.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER)
            if (expirationDate != null && expirationDate < now) {
                throw ExpiredKeyException(fingerprint, expirationDate)
            }

            return certificationKey.getSecretKey(certificationPubKey.keyIdentifier)
                ?: throw MissingSecretKeyException(fingerprint, certificationPubKey.keyIdentifier)
        }
    }
}
