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
package org.pgpainless.pgpainless.decryption_verification;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.pgpainless.key.OpenPgpV4Fingerprint;

public class PainlessResult {

    private final Set<Long> recipientKeyIds;
    private final OpenPgpV4Fingerprint decryptionFingerprint;
    private final Set<Long> unverifiedSignatureKeyIds;
    private final Set<OpenPgpV4Fingerprint> verifiedSignaturesFingerprints;

    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean integrityProtected;

    public PainlessResult(Set<Long> recipientKeyIds,
                          OpenPgpV4Fingerprint decryptionFingerprint,
                          SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                          CompressionAlgorithm algorithm,
                          boolean integrityProtected,
                          Set<Long> unverifiedSignatureKeyIds,
                          Set<OpenPgpV4Fingerprint> verifiedSignaturesFingerprints) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionFingerprint = decryptionFingerprint;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.compressionAlgorithm = algorithm;
        this.integrityProtected = integrityProtected;
        this.unverifiedSignatureKeyIds = Collections.unmodifiableSet(unverifiedSignatureKeyIds);
        this.verifiedSignaturesFingerprints = Collections.unmodifiableSet(verifiedSignaturesFingerprints);
    }

    public Set<Long> getRecipientKeyIds() {
        return recipientKeyIds;
    }

    public boolean isEncrypted() {
        return !getRecipientKeyIds().isEmpty();
    }

    public OpenPgpV4Fingerprint getDecryptionFingerprint() {
        return decryptionFingerprint;
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

    public Set<Long> getAllSignatureKeyFingerprints() {
        return unverifiedSignatureKeyIds;
    }

    public boolean isSigned() {
        return !unverifiedSignatureKeyIds.isEmpty();
    }

    public Set<OpenPgpV4Fingerprint> getVerifiedSignaturesFingerprints() {
        return verifiedSignaturesFingerprints;
    }

    public boolean isVerified() {
        return !verifiedSignaturesFingerprints.isEmpty();
    }

    public boolean containsVerifiedSignatureFrom(PGPPublicKeyRing publicKeys) throws PGPException {
        for (PGPPublicKey key : publicKeys) {
            OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(key);
            if (verifiedSignaturesFingerprints.contains(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    static Builder getBuilder() {
        return new Builder();
    }

    static class Builder {

        private final Set<Long> recipientFingerprints = new HashSet<>();
        private OpenPgpV4Fingerprint decryptionFingerprint;
        private final Set<Long> unverifiedSignatureKeyIds = new HashSet<>();
        private final Set<OpenPgpV4Fingerprint> verifiedSignatureFingerprints = new HashSet<>();
        private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.NULL;
        private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
        private boolean integrityProtected = false;

        public Builder addRecipientKeyId(Long keyId) {
            this.recipientFingerprints.add(keyId);
            return this;
        }

        public Builder setDecryptionFingerprint(OpenPgpV4Fingerprint fingerprint) {
            this.decryptionFingerprint = fingerprint;
            return this;
        }

        public Builder setCompressionAlgorithm(CompressionAlgorithm algorithm) {
            this.compressionAlgorithm = algorithm;
            return this;
        }

        public Builder addUnverifiedSignatureKeyId(Long keyId) {
            this.unverifiedSignatureKeyIds.add(keyId);
            return this;
        }

        public Builder addVerifiedSignatureFingerprint(OpenPgpV4Fingerprint fingerprint) {
            this.verifiedSignatureFingerprints.add(fingerprint);
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
            return new PainlessResult(recipientFingerprints, decryptionFingerprint, symmetricKeyAlgorithm, compressionAlgorithm, integrityProtected, unverifiedSignatureKeyIds, verifiedSignatureFingerprints);
        }
    }
}
