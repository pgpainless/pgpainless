/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.encryption_signing;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.MultiMap;

public final class EncryptionResult {

    private final SymmetricKeyAlgorithm encryptionAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;

    private final MultiMap<SubkeyIdentifier, PGPSignature> detachedSignatures;
    private final Set<SubkeyIdentifier> recipients;
    private final OpenPgpMetadata.FileInfo fileInfo;

    private EncryptionResult(SymmetricKeyAlgorithm encryptionAlgorithm,
                             CompressionAlgorithm compressionAlgorithm,
                             MultiMap<SubkeyIdentifier, PGPSignature> detachedSignatures,
                             Set<SubkeyIdentifier> recipients,
                             OpenPgpMetadata.FileInfo fileInfo) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.detachedSignatures = detachedSignatures;
        this.recipients = Collections.unmodifiableSet(recipients);
        this.fileInfo = fileInfo;
    }

    @Deprecated
    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return getEncryptionAlgorithm();
    }

    public SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public MultiMap<SubkeyIdentifier, PGPSignature> getDetachedSignatures() {
        return detachedSignatures;
    }

    public Set<SubkeyIdentifier> getRecipients() {
        return recipients;
    }

    public OpenPgpMetadata.FileInfo getFileInfo() {
        return fileInfo;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private SymmetricKeyAlgorithm encryptionAlgorithm;
        private CompressionAlgorithm compressionAlgorithm;

        private final MultiMap<SubkeyIdentifier, PGPSignature> detachedSignatures = new MultiMap<>();
        private Set<SubkeyIdentifier> recipients = new HashSet<>();
        private OpenPgpMetadata.FileInfo fileInfo;

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

        public Builder setFileInfo(OpenPgpMetadata.FileInfo fileInfo) {
            this.fileInfo = fileInfo;
            return this;
        }

        public EncryptionResult build() {
            if (encryptionAlgorithm == null) {
                throw new IllegalStateException("Encryption algorithm not set.");
            }
            if (compressionAlgorithm == null) {
                throw new IllegalStateException("Compression algorithm not set.");
            }
            if (fileInfo == null) {
                throw new IllegalStateException("File info not set.");
            }

            return new EncryptionResult(encryptionAlgorithm, compressionAlgorithm, detachedSignatures, recipients, fileInfo);
        }
    }
}
