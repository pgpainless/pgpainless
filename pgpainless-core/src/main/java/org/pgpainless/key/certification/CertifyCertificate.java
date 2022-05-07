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
import org.pgpainless.signature.builder.DirectKeySignatureBuilder;
import org.pgpainless.signature.builder.ThirdPartyCertificationSignatureBuilder;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.DateUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Date;

public class CertifyCertificate {

    CertificationOnUserId userIdOnCertificate(@Nonnull String userId, @Nonnull PGPPublicKeyRing certificate) {
        return new CertificationOnUserId(userId, certificate, CertificationType.GENERIC);
    }

    CertificationOnUserId userIdOnCertificate(@Nonnull String userid, @Nonnull PGPPublicKeyRing certificate, @Nonnull CertificationType certificationType) {
        return new CertificationOnUserId(userid, certificate, certificationType);
    }

    DelegationOnCertificate certificate(@Nonnull PGPPublicKeyRing certificate) {
        return certificate(certificate, null);
    }

    DelegationOnCertificate certificate(@Nonnull PGPPublicKeyRing certificate, @Nullable Trustworthiness trustworthiness) {
        return new DelegationOnCertificate(certificate, trustworthiness);
    }

    public static class CertificationOnUserId {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final CertificationType certificationType;

        CertificationOnUserId(@Nonnull String userId, @Nonnull PGPPublicKeyRing certificate, @Nonnull CertificationType certificationType) {
            this.userId = userId;
            this.certificate = certificate;
            this.certificationType = certificationType;
        }

        CertificationOnUserIdWithSubpackets withKey(@Nonnull PGPSecretKeyRing certificationKey, @Nonnull SecretKeyRingProtector protector) throws PGPException {
            PGPSecretKey secretKey = getCertificationSecretKey(certificationKey);

            ThirdPartyCertificationSignatureBuilder sigBuilder = new ThirdPartyCertificationSignatureBuilder(
                    certificationType.asSignatureType(), secretKey, protector);

            return new CertificationOnUserIdWithSubpackets(certificate, userId, sigBuilder);
        }
    }

    public static class CertificationOnUserIdWithSubpackets {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final ThirdPartyCertificationSignatureBuilder sigBuilder;

        CertificationOnUserIdWithSubpackets(@Nonnull PGPPublicKeyRing certificate, @Nonnull String userId, @Nonnull ThirdPartyCertificationSignatureBuilder sigBuilder) {
            this.certificate = certificate;
            this.userId = userId;
            this.sigBuilder = sigBuilder;
        }

        public CertificationResult withSubpackets(@Nonnull CertificationSubpackets.Callback subpacketCallback) throws PGPException {
            sigBuilder.applyCallback(subpacketCallback);
            return build();
        }

        public CertificationResult build() throws PGPException {
            PGPSignature signature = sigBuilder.build(certificate, userId);
            PGPPublicKeyRing certifiedCertificate = KeyRingUtils.injectCertification(certificate, userId, signature);
            return new CertificationResult(certifiedCertificate, signature);
        }
    }

    public static class DelegationOnCertificate {

        private final PGPPublicKeyRing certificate;
        private final Trustworthiness trustworthiness;

        DelegationOnCertificate(@Nonnull PGPPublicKeyRing certificate, @Nullable Trustworthiness trustworthiness) {
            this.certificate = certificate;
            this.trustworthiness = trustworthiness;
        }

        public DelegationOnCertificateWithSubpackets withKey(@Nonnull PGPSecretKeyRing certificationKey, @Nonnull SecretKeyRingProtector protector) throws PGPException {
            PGPSecretKey secretKey = getCertificationSecretKey(certificationKey);

            DirectKeySignatureBuilder sigBuilder = new DirectKeySignatureBuilder(secretKey, protector);
            if (trustworthiness != null) {
                sigBuilder.getHashedSubpackets().setTrust(true, trustworthiness.getDepth(), trustworthiness.getAmount());
            }
            return new DelegationOnCertificateWithSubpackets(certificate, sigBuilder);
        }
    }

    public static class DelegationOnCertificateWithSubpackets {

        private final PGPPublicKeyRing certificate;
        private final DirectKeySignatureBuilder sigBuilder;

        public DelegationOnCertificateWithSubpackets(@Nonnull PGPPublicKeyRing certificate, @Nonnull DirectKeySignatureBuilder sigBuilder) {
            this.certificate = certificate;
            this.sigBuilder = sigBuilder;
        }

        public CertificationResult withSubpackets(@Nonnull CertificationSubpackets.Callback subpacketsCallback) throws PGPException {
            sigBuilder.applyCallback(subpacketsCallback);
            return build();
        }

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

        @Nonnull
        public PGPSignature getCertification() {
            return certification;
        }

        @Nonnull
        public PGPPublicKeyRing getCertifiedCertificate() {
            return certificate;
        }
    }

    private static PGPSecretKey getCertificationSecretKey(PGPSecretKeyRing certificationKey) {
        Date now = DateUtil.now();
        KeyRingInfo info = PGPainless.inspectKeyRing(certificationKey, now);

        // We only support certification-capable primary keys
        OpenPgpFingerprint fingerprint = info.getFingerprint();
        PGPPublicKey certificationPubKey = info.getPublicKey(fingerprint);
        if (!info.isKeyValidlyBound(certificationPubKey.getKeyID())) {
            throw new KeyException.RevokedKeyException(fingerprint);
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
