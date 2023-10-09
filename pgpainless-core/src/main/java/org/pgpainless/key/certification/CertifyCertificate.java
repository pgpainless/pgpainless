// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.certification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CertificationType;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.Trustworthiness;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.signature.builder.ThirdPartyDirectKeySignatureBuilder;
import org.pgpainless.signature.builder.ThirdPartyCertificationSignatureBuilder;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.DateUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Date;

/**
 * API for creating certifications and delegations (Signatures) on keys.
 * This API can be used to sign another persons OpenPGP key.
 *
 * A certification over a user-id is thereby used to attest, that the user believes that the user-id really belongs
 * to the owner of the certificate.
 * A delegation over a key can be used to delegate trust by marking the certificate as a trusted introducer.
 */
public class CertifyCertificate {

    /**
     * Create a certification over a User-Id.
     * By default, this method will use {@link CertificationType#GENERIC} to create the signature.
     * If you need to create another type of certification, use
     * {@link #userIdOnCertificate(String, PGPPublicKeyRing, CertificationType)} instead.
     *
     * @param userId user-id to certify
     * @param certificate certificate
     * @return API
     */
    public CertificationOnUserId userIdOnCertificate(@Nonnull String userId,
                                                     @Nonnull PGPPublicKeyRing certificate) {
        return userIdOnCertificate(userId, certificate, CertificationType.GENERIC);
    }

    /**
     * Create a certification of the given {@link CertificationType} over a User-Id.
     *
     * @param userid user-id to certify
     * @param certificate certificate
     * @param certificationType type of signature
     * @return API
     */
    public CertificationOnUserId userIdOnCertificate(@Nonnull String userid,
                                                     @Nonnull PGPPublicKeyRing certificate,
                                                     @Nonnull CertificationType certificationType) {
        return new CertificationOnUserId(userid, certificate, certificationType);
    }

    /**
     * Create a delegation (direct key signature) over a certificate.
     * This can be used to mark a certificate as a trusted introducer
     * (see {@link #certificate(PGPPublicKeyRing, Trustworthiness)}).
     *
     * @param certificate certificate
     * @return API
     */
    public DelegationOnCertificate certificate(@Nonnull PGPPublicKeyRing certificate) {
        return certificate(certificate, null);
    }

    /**
     * Create a delegation (direct key signature) containing a {@link org.bouncycastle.bcpg.sig.TrustSignature} packet
     * over a certificate.
     * This can be used to mark a certificate as a trusted introducer.
     *
     * @param certificate certificate
     * @param trustworthiness trustworthiness of the certificate
     * @return API
     */
    public DelegationOnCertificate certificate(@Nonnull PGPPublicKeyRing certificate,
                                               @Nullable Trustworthiness trustworthiness) {
        return new DelegationOnCertificate(certificate, trustworthiness);
    }

    public static class CertificationOnUserId {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final CertificationType certificationType;

        CertificationOnUserId(@Nonnull String userId,
                              @Nonnull PGPPublicKeyRing certificate,
                              @Nonnull CertificationType certificationType) {
            this.userId = userId;
            this.certificate = certificate;
            this.certificationType = certificationType;
        }

        /**
         * Create the certification using the given key.
         *
         * @param certificationKey key used to create the certification
         * @param protector protector to unlock the certification key
         * @return API
         * @throws PGPException in case of an OpenPGP related error
         */
        public CertificationOnUserIdWithSubpackets withKey(@Nonnull PGPSecretKeyRing certificationKey,
                                                           @Nonnull SecretKeyRingProtector protector)
                throws PGPException {
            PGPSecretKey secretKey = getCertifyingSecretKey(certificationKey);

            ThirdPartyCertificationSignatureBuilder sigBuilder = new ThirdPartyCertificationSignatureBuilder(
                    certificationType.asSignatureType(), secretKey, protector);

            return new CertificationOnUserIdWithSubpackets(certificate, userId, sigBuilder);
        }
    }

    public static class CertificationOnUserIdWithSubpackets {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final ThirdPartyCertificationSignatureBuilder sigBuilder;

        CertificationOnUserIdWithSubpackets(@Nonnull PGPPublicKeyRing certificate,
                                            @Nonnull String userId,
                                            @Nonnull ThirdPartyCertificationSignatureBuilder sigBuilder) {
            this.certificate = certificate;
            this.userId = userId;
            this.sigBuilder = sigBuilder;
        }

        /**
         * Apply the given signature subpackets and build the certification.
         *
         * @param subpacketCallback callback to modify the signatures subpackets
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        public CertificationResult buildWithSubpackets(@Nonnull CertificationSubpackets.Callback subpacketCallback)
                throws PGPException {
            sigBuilder.applyCallback(subpacketCallback);
            return build();
        }

        /**
         * Build the certification signature.
         *
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        public CertificationResult build() throws PGPException {
            PGPSignature signature = sigBuilder.build(certificate, userId);
            PGPPublicKeyRing certifiedCertificate = KeyRingUtils.injectCertification(certificate, userId, signature);
            return new CertificationResult(certifiedCertificate, signature);
        }
    }

    public static class DelegationOnCertificate {

        private final PGPPublicKeyRing certificate;
        private final Trustworthiness trustworthiness;

        DelegationOnCertificate(@Nonnull PGPPublicKeyRing certificate,
                                @Nullable Trustworthiness trustworthiness) {
            this.certificate = certificate;
            this.trustworthiness = trustworthiness;
        }

        /**
         * Build the delegation using the given certification key.
         *
         * @param certificationKey key to create the certification with
         * @param protector protector to unlock the certification key
         * @return API
         * @throws PGPException in case of an OpenPGP related error
         */
        public DelegationOnCertificateWithSubpackets withKey(@Nonnull PGPSecretKeyRing certificationKey,
                                                             @Nonnull SecretKeyRingProtector protector)
                throws PGPException {
            PGPSecretKey secretKey = getCertifyingSecretKey(certificationKey);

            ThirdPartyDirectKeySignatureBuilder sigBuilder = new ThirdPartyDirectKeySignatureBuilder(secretKey, protector);
            if (trustworthiness != null) {
                sigBuilder.getHashedSubpackets().setTrust(true, trustworthiness.getDepth(), trustworthiness.getAmount());
            }
            return new DelegationOnCertificateWithSubpackets(certificate, sigBuilder);
        }
    }

    public static class DelegationOnCertificateWithSubpackets {

        private final PGPPublicKeyRing certificate;
        private final ThirdPartyDirectKeySignatureBuilder sigBuilder;

        DelegationOnCertificateWithSubpackets(@Nonnull PGPPublicKeyRing certificate,
                                              @Nonnull ThirdPartyDirectKeySignatureBuilder sigBuilder) {
            this.certificate = certificate;
            this.sigBuilder = sigBuilder;
        }

        /**
         * Apply the given signature subpackets and build the delegation signature.
         *
         * @param subpacketsCallback callback to modify the signatures subpackets
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        public CertificationResult buildWithSubpackets(@Nonnull CertificationSubpackets.Callback subpacketsCallback)
                throws PGPException {
            sigBuilder.applyCallback(subpacketsCallback);
            return build();
        }

        /**
         * Build the delegation signature.
         *
         * @return result
         * @throws PGPException in case of an OpenPGP related error
         */
        public CertificationResult build() throws PGPException {
            PGPPublicKey delegatedKey = certificate.getPublicKey();
            PGPSignature delegation = sigBuilder.build(delegatedKey);
            PGPPublicKeyRing delegatedCertificate = KeyRingUtils.injectCertification(certificate, delegatedKey, delegation);
            return new CertificationResult(delegatedCertificate, delegation);
        }
    }

    public static class CertificationResult {

        private final PGPPublicKeyRing certificate;
        private final PGPSignature certification;

        CertificationResult(@Nonnull PGPPublicKeyRing certificate, @Nonnull PGPSignature certification) {
            this.certificate = certificate;
            this.certification = certification;
        }

        /**
         * Return the signature.
         *
         * @return signature
         */
        @Nonnull
        public PGPSignature getCertification() {
            return certification;
        }

        /**
         * Return the certificate, which now contains the signature.
         *
         * @return certificate + signature
         */
        @Nonnull
        public PGPPublicKeyRing getCertifiedCertificate() {
            return certificate;
        }
    }

    private static PGPSecretKey getCertifyingSecretKey(PGPSecretKeyRing certificationKey) {
        Date now = DateUtil.now();
        KeyRingInfo info = PGPainless.inspectKeyRing(certificationKey, now);

        // We only support certification-capable primary keys
        OpenPgpFingerprint fingerprint = info.getFingerprint();
        PGPPublicKey certificationPubKey = info.getPublicKey(fingerprint);
        assert (certificationPubKey != null);
        if (!info.isKeyValidlyBound(certificationPubKey.getKeyID())) {
            throw new KeyException.RevokedKeyException(fingerprint);
        }

        if (!info.isUsableForThirdPartyCertification()) {
            throw new KeyException.UnacceptableThirdPartyCertificationKeyException(fingerprint);
        }

        Date expirationDate = info.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER);
        if (expirationDate != null && expirationDate.before(now)) {
            throw new KeyException.ExpiredKeyException(fingerprint, expirationDate);
        }

        PGPSecretKey secretKey = certificationKey.getSecretKey(certificationPubKey.getKeyID());
        if (secretKey == null) {
            throw new KeyException.MissingSecretKeyException(fingerprint, certificationPubKey.getKeyID());
        }
        return secretKey;
    }
}
