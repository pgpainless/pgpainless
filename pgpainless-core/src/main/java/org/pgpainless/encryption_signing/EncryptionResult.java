// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.MultiMap;

public final class EncryptionResult {

    private final SymmetricKeyAlgorithm encryptionAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;

    private final MultiMap<SubkeyIdentifier, PGPSignature> detachedSignatures;
    private final Set<SubkeyIdentifier> recipients;
    private final String fileName;
    private final Date modificationDate;
    private final StreamEncoding fileEncoding;

    private EncryptionResult(SymmetricKeyAlgorithm encryptionAlgorithm,
                             CompressionAlgorithm compressionAlgorithm,
                             MultiMap<SubkeyIdentifier, PGPSignature> detachedSignatures,
                             Set<SubkeyIdentifier> recipients,
                             String fileName,
                             Date modificationDate,
                             StreamEncoding encoding) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.detachedSignatures = detachedSignatures;
        this.recipients = Collections.unmodifiableSet(recipients);
        this.fileName = fileName;
        this.modificationDate = modificationDate;
        this.fileEncoding = encoding;
    }

    /**
     * Return the symmetric encryption algorithm used to encrypt the message.
     * @return symmetric encryption algorithm
     *
     * @deprecated use {@link #getEncryptionAlgorithm()} instead.
     */
    @Deprecated
    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return getEncryptionAlgorithm();
    }

    /**
     * Return the symmetric encryption algorithm used to encrypt the message.
     *
     * @return symmetric encryption algorithm
     * */
    public SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Return the compression algorithm that was used to compress the message before encryption/signing.
     *
     * @return compression algorithm
     */
    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    /**
     * Return a {@link MultiMap} of key identifiers and detached signatures that were generated for the message.
     * Each key of the map represents a signing key, which has one or more detached signatures associated with it.
     *
     * @return detached signatures
     */
    public MultiMap<SubkeyIdentifier, PGPSignature> getDetachedSignatures() {
        return detachedSignatures;
    }

    /**
     * Return the set of recipient encryption keys.
     *
     * @return recipients
     */
    public Set<SubkeyIdentifier> getRecipients() {
        return recipients;
    }

    /**
     * Return the file name of the encrypted/signed data.
     *
     * @return filename
     */
    public String getFileName() {
        return fileName;
    }

    /**
     * Return the modification date of the encrypted/signed file.
     *
     * @return modification date
     */
    public Date getModificationDate() {
        return modificationDate;
    }

    /**
     * Return the encoding format of the encrypted/signed data.
     *
     * @return encoding format
     */
    public StreamEncoding getFileEncoding() {
        return fileEncoding;
    }

    /**
     * Return true, if the message is marked as for-your-eyes-only.
     * This is typically done by setting the filename "_CONSOLE".
     *
     * @return is message for your eyes only?
     */
    public boolean isForYourEyesOnly() {
        return PGPLiteralData.CONSOLE.equals(getFileName());
    }

    /**
     * Returns true, if the message was encrypted for at least one subkey of the given certificate.
     *
     * @param certificate certificate
     * @return true if encrypted for 1+ subkeys, false otherwise.
     */
    public boolean isEncryptedFor(PGPPublicKeyRing certificate) {
        for (SubkeyIdentifier recipient : recipients) {
            if (certificate.getPublicKey().getKeyID() != recipient.getPrimaryKeyId()) {
                continue;
            }

            if (certificate.getPublicKey(recipient.getSubkeyId()) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Create a builder for the encryption result class.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private SymmetricKeyAlgorithm encryptionAlgorithm;
        private CompressionAlgorithm compressionAlgorithm;

        private final MultiMap<SubkeyIdentifier, PGPSignature> detachedSignatures = new MultiMap<>();
        private final Set<SubkeyIdentifier> recipients = new HashSet<>();
        private String fileName = "";
        private Date modificationDate = new Date(0L); // NOW
        private StreamEncoding encoding = StreamEncoding.BINARY;

        public Builder setEncryptionAlgorithm(SymmetricKeyAlgorithm encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
            return this;
        }

        public Builder setCompressionAlgorithm(CompressionAlgorithm compressionAlgorithm) {
            this.compressionAlgorithm = compressionAlgorithm;
            return this;
        }

        public Builder addRecipient(SubkeyIdentifier recipient) {
            this.recipients.add(recipient);
            return this;
        }

        public Builder addDetachedSignature(SubkeyIdentifier signingSubkeyIdentifier, PGPSignature detachedSignature) {
            this.detachedSignatures.put(signingSubkeyIdentifier, detachedSignature);
            return this;
        }

        public Builder setFileName(@Nonnull String fileName) {
            this.fileName = fileName;
            return this;
        }

        public Builder setModificationDate(@Nonnull Date modificationDate) {
            this.modificationDate = modificationDate;
            return this;
        }

        public Builder setFileEncoding(StreamEncoding fileEncoding) {
            this.encoding = fileEncoding;
            return this;
        }

        public EncryptionResult build() {
            if (encryptionAlgorithm == null) {
                throw new IllegalStateException("Encryption algorithm not set.");
            }
            if (compressionAlgorithm == null) {
                throw new IllegalStateException("Compression algorithm not set.");
            }

            return new EncryptionResult(encryptionAlgorithm, compressionAlgorithm, detachedSignatures, recipients,
                    fileName, modificationDate, encoding);
        }
    }
}
