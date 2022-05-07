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
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.signature.builder.ThirdPartyCertificationSignatureBuilder;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.DateUtil;

import java.util.Date;

public class CertifyCertificate {

    CertifyUserId certifyUserId(PGPPublicKeyRing certificate, String userId) {
        return new CertifyUserId(certificate, userId);
    }

    public static class CertifyUserId {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final CertificationType certificationType;

        CertifyUserId(PGPPublicKeyRing certificate, String userId) {
            this(certificate, userId, CertificationType.GENERIC);
        }

        CertifyUserId(PGPPublicKeyRing certificate, String userId, CertificationType certificationType) {
            this.certificate = certificate;
            this.userId = userId;
            this.certificationType = certificationType;
        }

        CertifyUserIdWithSubpackets withKey(PGPSecretKeyRing certificationKey, SecretKeyRingProtector protector) throws PGPException {
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

            ThirdPartyCertificationSignatureBuilder sigBuilder = new ThirdPartyCertificationSignatureBuilder(
                    certificationType.asSignatureType(), secretKey, protector);

            return new CertifyUserIdWithSubpackets(certificate, userId, sigBuilder);
        }
    }

    public static class CertifyUserIdWithSubpackets {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final ThirdPartyCertificationSignatureBuilder sigBuilder;

        CertifyUserIdWithSubpackets(PGPPublicKeyRing certificate, String userId, ThirdPartyCertificationSignatureBuilder sigBuilder) {
            this.certificate = certificate;
            this.userId = userId;
            this.sigBuilder = sigBuilder;
        }

        public CertifyUserIdResult withSubpackets(CertificationSubpackets.Callback subpacketCallback) throws PGPException {
            sigBuilder.applyCallback(subpacketCallback);
            return build();
        }

        public CertifyUserIdResult build() throws PGPException {
            PGPSignature signature = sigBuilder.build(certificate, userId);

            return new CertifyUserIdResult(certificate, userId, signature);
        }
    }

    public static class CertifyUserIdResult {

        private final PGPPublicKeyRing certificate;
        private final String userId;
        private final PGPSignature certification;

        CertifyUserIdResult(PGPPublicKeyRing certificate, String userId, PGPSignature certification) {
            this.certificate = certificate;
            this.userId = userId;
            this.certification = certification;
        }

        public PGPSignature getCertification() {
            return certification;
        }

        public PGPPublicKeyRing getCertifiedCertificate() {
            // inject the signature
            PGPPublicKeyRing certified = KeyRingUtils.injectCertification(certificate, userId, certification);
            return certified;
        }
    }
}
