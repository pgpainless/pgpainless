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
package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

public class PainlessResult {

    private final Set<Long> recipientKeyIds;
    private final Long decryptionKeyId;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean integrityProtected;
    private final Set<Long> signatureKeyIds;
    private final Set<Long> verifiedSignatureKeyIds;

    public PainlessResult(Set<Long> recipientKeyIds,
                          Long decryptionKeyId,
                          SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                          CompressionAlgorithm algorithm,
                          boolean integrityProtected,
                          Set<Long> signatureKeyIds,
                          Set<Long> verifiedSignatureKeyIds) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionKeyId = decryptionKeyId;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.compressionAlgorithm = algorithm;
        this.integrityProtected = integrityProtected;
        this.signatureKeyIds = Collections.unmodifiableSet(signatureKeyIds);
        this.verifiedSignatureKeyIds = Collections.unmodifiableSet(verifiedSignatureKeyIds);
    }

    public Set<Long> getRecipientKeyIds() {
        return recipientKeyIds;
    }

    public boolean isEncrypted() {
        return !getRecipientKeyIds().isEmpty();
    }

    public Long getDecryptionKeyId() {
        return decryptionKeyId;
    }

    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public boolean isIntegrityProtected() {
        return integrityProtected;
    }

    public Set<Long> getAllSignatureKeyIds() {
        return signatureKeyIds;
    }

    public boolean isSigned() {
        return !signatureKeyIds.isEmpty();
    }

    public Set<Long> getVerifiedSignatureKeyIds() {
        return verifiedSignatureKeyIds;
    }

    public boolean isVerified() {
        return !verifiedSignatureKeyIds.isEmpty();
    }

    public boolean containsVerifiedSignatureFrom(PGPPublicKeyRing publicKeys) {
        for (PGPPublicKey key : publicKeys) {
            long id = key.getKeyID();
            if (verifiedSignatureKeyIds.contains(id)) {
                return true;
            }
        }
        return false;
    }

    static Builder getBuilder() {
        return new Builder();
    }

    static class Builder {

        private final Set<Long> recipientKeyIds = new HashSet<>();
        private Long decryptionKeyId;
        private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.NULL;
        private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
        private boolean integrityProtected = false;
        private final Set<Long> signatureKeyIds = new HashSet<>();
        private final Set<Long> verifiedSignatureKeyIds = new HashSet<>();

        public Builder addRecipientKeyId(long id) {
            this.recipientKeyIds.add(id);
            return this;
        }

        public Builder setDecryptionKeyId(long id) {
            this.decryptionKeyId = id;
            return this;
        }

        public Builder setCompressionAlgorithm(CompressionAlgorithm algorithm) {
            this.compressionAlgorithm = algorithm;
            return this;
        }

        public Builder addSignatureKeyId(long id) {
            this.signatureKeyIds.add(id);
            return this;
        }

        public Builder addVerifiedSignatureKeyId(long id) {
            this.verifiedSignatureKeyIds.add(id);
            return this;
        }

        public Builder setSymmetricKeyAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
            this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            return this;
        }

        public Builder setIntegrityProtected(boolean integrityProtected) {
            this.integrityProtected = integrityProtected;
            return this;
        }

        public PainlessResult build() {
            return new PainlessResult(recipientKeyIds, decryptionKeyId, symmetricKeyAlgorithm, compressionAlgorithm, integrityProtected, signatureKeyIds, verifiedSignatureKeyIds);
        }
    }
}
