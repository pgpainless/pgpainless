// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.util.DateUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Date;

public abstract class KeyException extends RuntimeException {

    private final OpenPgpFingerprint fingerprint;

    protected KeyException(@Nonnull String message, @Nonnull OpenPgpFingerprint fingerprint) {
        super(message);
        this.fingerprint = fingerprint;
    }

    protected KeyException(@Nonnull String message, @Nonnull OpenPgpFingerprint fingerprint, @Nonnull Throwable underlying) {
        super(message, underlying);
        this.fingerprint = fingerprint;
    }

    public OpenPgpFingerprint getFingerprint() {
        return fingerprint;
    }

    public static class ExpiredKeyException extends KeyException {

        public ExpiredKeyException(@Nonnull OpenPGPCertificate cert, @Nonnull Date expirationDate) {
            this(OpenPgpFingerprint.of(cert), expirationDate);
        }

        public ExpiredKeyException(@Nonnull OpenPgpFingerprint fingerprint, @Nonnull Date expirationDate) {
            super("Key " + fingerprint + " is expired. Expiration date: " + DateUtil.formatUTCDate(expirationDate), fingerprint);
        }
    }

    public static class RevokedKeyException extends KeyException {

        public RevokedKeyException(@Nonnull OpenPgpFingerprint fingerprint) {
            super("Key " + fingerprint + " appears to be revoked.", fingerprint);
        }

        public RevokedKeyException(@Nonnull OpenPGPCertificate.OpenPGPComponentKey key) {
            super("Subkey " + key.getKeyIdentifier() + " appears to be revoked.",
                    OpenPgpFingerprint.of(key));
        }

        public RevokedKeyException(@Nonnull OpenPGPCertificate cert) {
            super("Key or certificate " + cert.getKeyIdentifier() + " appears to be revoked.",
                    OpenPgpFingerprint.of(cert));
        }
    }

    public static class UnacceptableEncryptionKeyException extends KeyException {

        public UnacceptableEncryptionKeyException(@Nonnull OpenPGPCertificate cert) {
            this(OpenPgpFingerprint.of(cert));
        }

        public UnacceptableEncryptionKeyException(@Nonnull OpenPGPCertificate.OpenPGPComponentKey subkey) {
            super("Subkey " + subkey.getKeyIdentifier() + " is not an acceptable encryption key.",
                    OpenPgpFingerprint.of(subkey));
        }

        public UnacceptableEncryptionKeyException(@Nonnull OpenPgpFingerprint fingerprint) {
            super("Key " + fingerprint + " has no acceptable encryption key.", fingerprint);
        }

        public UnacceptableEncryptionKeyException(@Nonnull PublicKeyAlgorithmPolicyException reason) {
            super("Key " + reason.getFingerprint() + " has no acceptable encryption key.", reason.getFingerprint(), reason);
        }
    }

    public static class UnacceptableSigningKeyException extends KeyException {

        public UnacceptableSigningKeyException(OpenPGPCertificate certificate) {
            this(OpenPgpFingerprint.of(certificate));
        }

        public UnacceptableSigningKeyException(OpenPGPCertificate.OpenPGPComponentKey subkey) {
            this(OpenPgpFingerprint.of(subkey));
        }

        public UnacceptableSigningKeyException(@Nonnull OpenPgpFingerprint fingerprint) {
            super("Key " + fingerprint + " has no acceptable signing key.", fingerprint);
        }

        public UnacceptableSigningKeyException(@Nonnull PublicKeyAlgorithmPolicyException reason) {
            super("Key " + reason.getFingerprint() + " has no acceptable signing key.", reason.getFingerprint(), reason);
        }
    }

    public static class UnacceptableThirdPartyCertificationKeyException extends KeyException {

        public UnacceptableThirdPartyCertificationKeyException(@Nonnull OpenPgpFingerprint fingerprint) {
            super("Key " + fingerprint + " has no acceptable certification key.", fingerprint);
        }
    }

    public static class UnacceptableSelfSignatureException extends KeyException {

        public UnacceptableSelfSignatureException(@Nonnull OpenPGPCertificate cert) {
            this(OpenPgpFingerprint.of(cert));
        }

        public UnacceptableSelfSignatureException(@Nonnull OpenPgpFingerprint fingerprint) {
            super("Key " + fingerprint + " does not have a valid/acceptable signature to derive an expiration date from.", fingerprint);
        }
    }

    public static class MissingSecretKeyException extends KeyException {

        private final KeyIdentifier missingSecretKeyIdentifier;

        public MissingSecretKeyException(@Nonnull OpenPGPCertificate.OpenPGPComponentKey publicKey) {
            this(OpenPgpFingerprint.of(publicKey.getCertificate()), publicKey.getKeyIdentifier());
        }

        public MissingSecretKeyException(@Nonnull OpenPgpFingerprint fingerprint, KeyIdentifier keyIdentifier) {
            super("Key " + fingerprint + " does not contain a secret key for public key " + keyIdentifier, fingerprint);
            this.missingSecretKeyIdentifier = keyIdentifier;
        }

        @Deprecated
        public MissingSecretKeyException(@Nonnull OpenPgpFingerprint fingerprint, long keyId) {
            this(fingerprint, new KeyIdentifier(keyId));
        }

        public KeyIdentifier getMissingSecretKeyIdentifier() {
            return missingSecretKeyIdentifier;
        }
    }

    public static class PublicKeyAlgorithmPolicyException extends KeyException {

        private final KeyIdentifier violatingSubkeyId;

        public PublicKeyAlgorithmPolicyException(@Nonnull OpenPGPCertificate.OpenPGPComponentKey subkey,
                                                 @Nonnull PublicKeyAlgorithm algorithm,
                                                 int bitSize) {
            super("Subkey " + subkey.getKeyIdentifier() + " of key " + subkey.getCertificate().getKeyIdentifier() +
                    " is violating the Public Key Algorithm Policy:\n" +
                    algorithm + " of size " + bitSize + " is not acceptable.", OpenPgpFingerprint.of(subkey));
            this.violatingSubkeyId = subkey.getKeyIdentifier();
        }

        public PublicKeyAlgorithmPolicyException(@Nonnull OpenPgpFingerprint fingerprint,
                                                 long keyId,
                                                 @Nonnull PublicKeyAlgorithm algorithm,
                                                 int bitSize) {
            super("Subkey " + Long.toHexString(keyId) + " of key " + fingerprint + " is violating the Public Key Algorithm Policy:\n" +
                    algorithm + " of size " + bitSize + " is not acceptable.", fingerprint);
            this.violatingSubkeyId = new KeyIdentifier(keyId);
        }

        public KeyIdentifier getViolatingSubkeyId() {
             return violatingSubkeyId;
        }
    }

    public static class UnboundUserIdException extends KeyException {

        public UnboundUserIdException(@Nonnull OpenPgpFingerprint fingerprint, @Nonnull String userId,
                                      @Nullable PGPSignature userIdSignature, @Nullable PGPSignature userIdRevocation) {
            super(errorMessage(fingerprint, userId, userIdSignature, userIdRevocation), fingerprint);
        }

        private static String errorMessage(@Nonnull OpenPgpFingerprint fingerprint, @Nonnull String userId,
                                           @Nullable PGPSignature userIdSignature, @Nullable PGPSignature userIdRevocation) {
            String errorMessage = "UserID '" + userId + "' is not valid for key " + fingerprint + ": ";
            if (userIdSignature == null) {
                return errorMessage + "Missing binding signature.";
            }
            if (userIdRevocation != null) {
                return errorMessage + "UserID is revoked.";
            }
            return errorMessage + "Unacceptable binding signature.";
        }
    }
}
