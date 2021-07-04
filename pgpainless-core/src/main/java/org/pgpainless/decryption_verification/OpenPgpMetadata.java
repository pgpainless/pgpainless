/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.decryption_verification;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.signature.DetachedSignature;
import org.pgpainless.signature.OnePassSignature;

public class OpenPgpMetadata {

    private final Set<Long> recipientKeyIds;
    private final SubkeyIdentifier decryptionKey;
    private final List<OnePassSignature> onePassSignatures;
    private final List<DetachedSignature> detachedSignatures;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final FileInfo fileInfo;

    public OpenPgpMetadata(Set<Long> recipientKeyIds,
                           SubkeyIdentifier decryptionKey,
                           SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                           CompressionAlgorithm algorithm,
                           List<OnePassSignature> onePassSignatures,
                           List<DetachedSignature> detachedSignatures,
                           FileInfo fileInfo) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionKey = decryptionKey;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.compressionAlgorithm = algorithm;
        this.detachedSignatures = Collections.unmodifiableList(detachedSignatures);
        this.onePassSignatures = Collections.unmodifiableList(onePassSignatures);
        this.fileInfo = fileInfo;
    }

    public Set<Long> getRecipientKeyIds() {
        return recipientKeyIds;
    }

    public boolean isEncrypted() {
        return symmetricKeyAlgorithm != SymmetricKeyAlgorithm.NULL && !getRecipientKeyIds().isEmpty();
    }

    public SubkeyIdentifier getDecryptionKey() {
        return decryptionKey;
    }

    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public Set<PGPSignature> getSignatures() {
        Set<PGPSignature> signatures = new HashSet<>();
        for (DetachedSignature detachedSignature : detachedSignatures) {
            signatures.add(detachedSignature.getSignature());
        }
        for (OnePassSignature onePassSignature : onePassSignatures) {
            signatures.add(onePassSignature.getSignature());
        }
        return signatures;
    }

    public boolean isSigned() {
        return !getSignatures().isEmpty();
    }

    public Map<SubkeyIdentifier, PGPSignature> getVerifiedSignatures() {
        Map<SubkeyIdentifier, PGPSignature> verifiedSignatures = new ConcurrentHashMap<>();
        for (DetachedSignature detachedSignature : detachedSignatures) {
            if (detachedSignature.isVerified()) {
                verifiedSignatures.put(detachedSignature.getSigningKeyIdentifier(), detachedSignature.getSignature());
            }
        }
        for (OnePassSignature onePassSignature : onePassSignatures) {
            if (onePassSignature.isVerified()) {
                verifiedSignatures.put(onePassSignature.getSigningKey(), onePassSignature.getSignature());
            }
        }

        return verifiedSignatures;
    }

    public boolean isVerified() {
        return !getVerifiedSignatures().isEmpty();
    }

    public boolean containsVerifiedSignatureFrom(PGPPublicKeyRing publicKeys) {
        for (PGPPublicKey key : publicKeys) {
            OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(key);
            if (containsVerifiedSignatureFrom(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    public boolean containsVerifiedSignatureFrom(OpenPgpV4Fingerprint fingerprint) {
        for (SubkeyIdentifier verifiedSigningKey : getVerifiedSignatures().keySet()) {
            if (verifiedSigningKey.getPrimaryKeyFingerprint().equals(fingerprint) ||
                    verifiedSigningKey.getSubkeyFingerprint().equals(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    public static class Signature {
        protected final PGPSignature signature;
        protected final OpenPgpV4Fingerprint fingerprint;

        public Signature(PGPSignature signature, OpenPgpV4Fingerprint fingerprint) {
            this.signature = signature;
            this.fingerprint = fingerprint;
        }
    }

    public FileInfo getFileInfo() {
        return fileInfo;
    }

    public static class FileInfo {
        public static final String FOR_YOUR_EYES_ONLY = PGPLiteralData.CONSOLE;

        protected final String fileName;
        protected final Date modicationDate;
        protected final StreamEncoding streamEncoding;

        public FileInfo(String fileName, Date modicationDate, StreamEncoding streamEncoding) {
            this.fileName = fileName == null ? "" : fileName;
            this.modicationDate = modicationDate == null ? PGPLiteralData.NOW : modicationDate;
            this.streamEncoding = streamEncoding;
        }

        public static FileInfo binaryStream() {
            return new FileInfo("", null, StreamEncoding.BINARY);
        }

        public static FileInfo forYourEyesOnly() {
            return new FileInfo(FOR_YOUR_EYES_ONLY, null, StreamEncoding.BINARY);
        }

        public String getFileName() {
            return fileName;
        }

        public boolean isForYourEyesOnly() {
            return FOR_YOUR_EYES_ONLY.equals(fileName);
        }

        public Date getModificationDate() {
            return modicationDate;
        }

        public StreamEncoding getStreamFormat() {
            return streamEncoding;
        }

        @Override
        public boolean equals(Object other) {
            if (other == null) {
                return false;
            }
            if (this == other) {
                return true;
            }
            if (!(other instanceof FileInfo)) {
                return false;
            }

            FileInfo o = (FileInfo) other;

            if (getFileName() != null) {
                if (!getFileName().equals(o.getFileName())) {
                    return false;
                }
            } else {
                if (o.getFileName() != null) {
                    return false;
                }
            }

            if (getModificationDate() != null) {
                if (o.getModificationDate() == null) {
                    return false;
                }
                long diff = Math.abs(getModificationDate().getTime() - o.getModificationDate().getTime());
                if (diff > 1000) {
                    return false;
                }
            } else {
                if (o.getModificationDate() != null) {
                    return false;
                }
            }

            return getStreamFormat() == o.getStreamFormat();
        }
    }

    public static Builder getBuilder() {
        return new Builder();
    }

    public static class Builder {

        private final Set<Long> recipientFingerprints = new HashSet<>();
        private SubkeyIdentifier decryptionKey;
        private final List<DetachedSignature> detachedSignatures = new ArrayList<>();
        private final List<OnePassSignature> onePassSignatures = new ArrayList<>();
        private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.NULL;
        private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
        private FileInfo fileInfo;

        public Builder addRecipientKeyId(Long keyId) {
            this.recipientFingerprints.add(keyId);
            return this;
        }

        public Builder setDecryptionKey(SubkeyIdentifier decryptionKey) {
            this.decryptionKey = decryptionKey;
            return this;
        }

        public Builder setCompressionAlgorithm(CompressionAlgorithm algorithm) {
            this.compressionAlgorithm = algorithm;
            return this;
        }

        public List<DetachedSignature> getDetachedSignatures() {
            return detachedSignatures;
        }

        public Builder setSymmetricKeyAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
            this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            return this;
        }

        public void addDetachedSignature(DetachedSignature signature) {
            this.detachedSignatures.add(signature);
        }

        public void addOnePassSignature(OnePassSignature onePassSignature) {
            this.onePassSignatures.add(onePassSignature);
        }

        public Builder setFileInfo(FileInfo fileInfo) {
            this.fileInfo = fileInfo;
            return this;
        }

        public OpenPgpMetadata build() {
            return new OpenPgpMetadata(recipientFingerprints, decryptionKey,
                    symmetricKeyAlgorithm, compressionAlgorithm,
                    onePassSignatures, detachedSignatures, fileInfo);
        }
    }
}
