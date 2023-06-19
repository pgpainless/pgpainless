// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.SessionKey;

/**
 * Legacy class containing metadata about an OpenPGP message.
 * It is advised to use {@link MessageMetadata} instead.
 *
 * TODO: Remove in 1.6.X
 */
public class OpenPgpMetadata {

    private final Set<Long> recipientKeyIds;
    private final SubkeyIdentifier decryptionKey;
    private final List<SignatureVerification> verifiedInbandSignatures;
    private final List<SignatureVerification.Failure> invalidInbandSignatures;
    private final List<SignatureVerification> verifiedDetachedSignatures;
    private final List<SignatureVerification.Failure> invalidDetachedSignatures;
    private final SessionKey sessionKey;
    private final CompressionAlgorithm compressionAlgorithm;
    private final String fileName;
    private final Date modificationDate;
    private final StreamEncoding fileEncoding;
    private final boolean cleartextSigned;

    public OpenPgpMetadata(Set<Long> recipientKeyIds,
                           SubkeyIdentifier decryptionKey,
                           SessionKey sessionKey,
                           CompressionAlgorithm algorithm,
                           List<SignatureVerification> verifiedInbandSignatures,
                           List<SignatureVerification.Failure> invalidInbandSignatures,
                           List<SignatureVerification> verifiedDetachedSignatures,
                           List<SignatureVerification.Failure> invalidDetachedSignatures,
                           String fileName,
                           Date modificationDate,
                           StreamEncoding fileEncoding,
                           boolean cleartextSigned) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionKey = decryptionKey;
        this.sessionKey = sessionKey;
        this.compressionAlgorithm = algorithm;
        this.verifiedInbandSignatures = Collections.unmodifiableList(verifiedInbandSignatures);
        this.invalidInbandSignatures = Collections.unmodifiableList(invalidInbandSignatures);
        this.verifiedDetachedSignatures = Collections.unmodifiableList(verifiedDetachedSignatures);
        this.invalidDetachedSignatures = Collections.unmodifiableList(invalidDetachedSignatures);
        this.fileName = fileName;
        this.modificationDate = modificationDate;
        this.fileEncoding = fileEncoding;
        this.cleartextSigned = cleartextSigned;
    }

    /**
     * Return a set of key-ids the messages was encrypted for.
     *
     * @return recipient ids
     */
    public @Nonnull Set<Long> getRecipientKeyIds() {
        return recipientKeyIds;
    }

    /**
     * Return true, if the message was encrypted.
     *
     * @return true if encrypted, false otherwise
     */
    public boolean isEncrypted() {
        return sessionKey != null && sessionKey.getAlgorithm() != SymmetricKeyAlgorithm.NULL;
    }

    /**
     * Return the {@link SubkeyIdentifier} of the key that was used to decrypt the message.
     * This can be null if the message was decrypted using a {@link org.pgpainless.util.Passphrase}, or if it was not
     * encrypted at all (e.g. signed only).
     *
     * @return subkey identifier of decryption key
     */
    public @Nullable SubkeyIdentifier getDecryptionKey() {
        return decryptionKey;
    }

    /**
     * Return the algorithm that was used to symmetrically encrypt the message.
     *
     * @return encryption algorithm
     */
    public @Nullable SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return sessionKey == null ? null : sessionKey.getAlgorithm();
    }

    public @Nullable SessionKey getSessionKey() {
        return sessionKey;
    }

    /**
     * Return the {@link CompressionAlgorithm} that was used to compress the message.
     *
     * @return compression algorithm
     */
    public @Nullable CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    /**
     * Return a set of all signatures on the message.
     * Note: This method returns just the signatures. There is no guarantee that the signatures are verified or even correct.
     *
     * Use {@link #getVerifiedSignatures()} instead to get all verified signatures.
     * @return unverified and verified signatures
     */
    public @Nonnull Set<PGPSignature> getSignatures() {
        Set<PGPSignature> signatures = new HashSet<>();
        for (SignatureVerification v : getVerifiedDetachedSignatures()) {
            signatures.add(v.getSignature());
        }
        for (SignatureVerification v : getVerifiedInbandSignatures()) {
            signatures.add(v.getSignature());
        }
        for (SignatureVerification.Failure f : getInvalidDetachedSignatures()) {
            signatures.add(f.getSignatureVerification().getSignature());
        }
        for (SignatureVerification.Failure f : getInvalidInbandSignatures()) {
            signatures.add(f.getSignatureVerification().getSignature());
        }
        return signatures;
    }

    /**
     * Return true if the message contained at least one signature.
     *
     * Note: This method does not reflect, whether the signature on the message is correct.
     * Use {@link #isVerified()} instead to determine, if the message carries a verifiable signature.
     *
     * @return true if message contains at least one unverified or verified signature, false otherwise.
     */
    public boolean isSigned() {
        return !getSignatures().isEmpty();
    }

    /**
     * Return a map of all verified signatures on the message.
     * The map contains verified signatures as value, with the {@link SubkeyIdentifier} of the key that was used to verify
     * the signature as the maps keys.
     *
     * @return verified detached and one-pass signatures
     */
    public Map<SubkeyIdentifier, PGPSignature> getVerifiedSignatures() {
        Map<SubkeyIdentifier, PGPSignature> verifiedSignatures = new ConcurrentHashMap<>();
        for (SignatureVerification detachedSignature : getVerifiedDetachedSignatures()) {
            verifiedSignatures.put(detachedSignature.getSigningKey(), detachedSignature.getSignature());
        }
        for (SignatureVerification inbandSignatures : verifiedInbandSignatures) {
            verifiedSignatures.put(inbandSignatures.getSigningKey(), inbandSignatures.getSignature());
        }

        return verifiedSignatures;
    }

    public List<SignatureVerification> getVerifiedInbandSignatures() {
        return verifiedInbandSignatures;
    }

    public List<SignatureVerification> getVerifiedDetachedSignatures() {
        return verifiedDetachedSignatures;
    }

    public List<SignatureVerification.Failure> getInvalidInbandSignatures() {
        return invalidInbandSignatures;
    }

    public List<SignatureVerification.Failure> getInvalidDetachedSignatures() {
        return invalidDetachedSignatures;
    }

    /**
     * Return true, if the message is signed and at least one signature on the message was verified successfully.
     *
     * @return true if message is verified, false otherwise
     */
    public boolean isVerified() {
        return !getVerifiedSignatures().isEmpty();
    }

    /**
     * Return true, if the message contains at least one verified signature made by a key in the
     * given certificate.
     *
     * @param certificate certificate
     * @return true if message was signed by the certificate (and the signature is valid), false otherwise
     */
    public boolean containsVerifiedSignatureFrom(PGPPublicKeyRing certificate) {
        for (PGPPublicKey key : certificate) {
            OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(key);
            if (containsVerifiedSignatureFrom(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return true, if the message contains at least one valid signature made by the key with the given
     * fingerprint, false otherwise.
     *
     * The fingerprint might be of the signing subkey, or the primary key of the signing certificate.
     *
     * @param fingerprint fingerprint of primary key or signing subkey
     * @return true if validly signed, false otherwise
     */
    public boolean containsVerifiedSignatureFrom(OpenPgpFingerprint fingerprint) {
        for (SubkeyIdentifier verifiedSigningKey : getVerifiedSignatures().keySet()) {
            if (verifiedSigningKey.getPrimaryKeyFingerprint().equals(fingerprint) ||
                    verifiedSigningKey.getSubkeyFingerprint().equals(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return the name of the encrypted / signed file.
     *
     * @return file name
     */
    public String getFileName() {
        return fileName;
    }

    /**
     * Return true, if the encrypted data is intended for your eyes only.
     *
     * @return true if for-your-eyes-only
     */
    public boolean isForYourEyesOnly() {
        return PGPLiteralData.CONSOLE.equals(getFileName());
    }

    /**
     * Return the modification date of the encrypted / signed file.
     *
     * @return modification date
     */
    public Date getModificationDate() {
        return modificationDate;
    }

    /**
     * Return the encoding format of the encrypted / signed file.
     *
     * @return encoding
     */
    public StreamEncoding getFileEncoding() {
        return fileEncoding;
    }

    /**
     * Return true if the message was signed using the cleartext signature framework.
     *
     * @return true if cleartext signed.
     */
    public boolean isCleartextSigned() {
        return cleartextSigned;
    }

    public static Builder getBuilder() {
        return new Builder();
    }

    public static class Builder {

        private final Set<Long> recipientFingerprints = new HashSet<>();
        private SessionKey sessionKey;
        private SubkeyIdentifier decryptionKey;
        private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
        private String fileName;
        private StreamEncoding fileEncoding;
        private Date modificationDate;
        private boolean cleartextSigned = false;

        private final List<SignatureVerification> verifiedInbandSignatures = new ArrayList<>();
        private final List<SignatureVerification> verifiedDetachedSignatures = new ArrayList<>();
        private final List<SignatureVerification.Failure> invalidInbandSignatures = new ArrayList<>();
        private final List<SignatureVerification.Failure> invalidDetachedSignatures = new ArrayList<>();


        public Builder addRecipientKeyId(Long keyId) {
            this.recipientFingerprints.add(keyId);
            return this;
        }

        public Builder setDecryptionKey(SubkeyIdentifier decryptionKey) {
            this.decryptionKey = decryptionKey;
            return this;
        }

        public Builder setSessionKey(SessionKey sessionKey) {
            this.sessionKey = sessionKey;
            return this;
        }

        public Builder setCompressionAlgorithm(CompressionAlgorithm algorithm) {
            this.compressionAlgorithm = algorithm;
            return this;
        }

        public Builder setFileName(@Nullable String fileName) {
            this.fileName = fileName;
            return this;
        }

        public Builder setModificationDate(Date modificationDate) {
            this.modificationDate = modificationDate;
            return this;
        }

        public Builder setFileEncoding(StreamEncoding encoding) {
            this.fileEncoding = encoding;
            return this;
        }

        public Builder addVerifiedInbandSignature(SignatureVerification signatureVerification) {
            this.verifiedInbandSignatures.add(signatureVerification);
            return this;
        }

        public Builder addVerifiedDetachedSignature(SignatureVerification signatureVerification) {
            this.verifiedDetachedSignatures.add(signatureVerification);
            return this;
        }

        public Builder addInvalidInbandSignature(SignatureVerification signatureVerification, SignatureValidationException e) {
            this.invalidInbandSignatures.add(new SignatureVerification.Failure(signatureVerification, e));
            return this;
        }

        public Builder addInvalidDetachedSignature(SignatureVerification signatureVerification, SignatureValidationException e) {
            this.invalidDetachedSignatures.add(new SignatureVerification.Failure(signatureVerification, e));
            return this;
        }

        public Builder setCleartextSigned() {
            this.cleartextSigned = true;
            return this;
        }

        public OpenPgpMetadata build() {
            return new OpenPgpMetadata(
                    recipientFingerprints, decryptionKey,
                    sessionKey, compressionAlgorithm,
                    verifiedInbandSignatures, invalidInbandSignatures,
                    verifiedDetachedSignatures, invalidDetachedSignatures,
                    fileName, modificationDate, fileEncoding, cleartextSigned);
        }
    }
}
