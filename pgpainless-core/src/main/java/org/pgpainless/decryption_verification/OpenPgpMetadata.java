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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class OpenPgpMetadata {

    private final Set<Long> recipientKeyIds;
    private final OpenPgpV4Fingerprint decryptionFingerprint;
    private final Set<PGPSignature> signatures;
    private final Set<Long> signatureKeyIds;
    private final Map<OpenPgpV4Fingerprint, PGPSignature> verifiedSignatures;
    private final Set<OpenPgpV4Fingerprint> verifiedSignaturesFingerprints;

    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean integrityProtected;

    public OpenPgpMetadata(Set<Long> recipientKeyIds,
                           OpenPgpV4Fingerprint decryptionFingerprint,
                           SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                           CompressionAlgorithm algorithm,
                           boolean integrityProtected,
                           Set<PGPSignature> signatures,
                           Set<Long> signatureKeyIds,
                           Map<OpenPgpV4Fingerprint, PGPSignature> verifiedSignatures,
                           Set<OpenPgpV4Fingerprint> verifiedSignaturesFingerprints) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionFingerprint = decryptionFingerprint;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.compressionAlgorithm = algorithm;
        this.integrityProtected = integrityProtected;
        this.signatures = Collections.unmodifiableSet(signatures);
        this.signatureKeyIds = Collections.unmodifiableSet(signatureKeyIds);
        this.verifiedSignatures = Collections.unmodifiableMap(verifiedSignatures);
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

    public Set<PGPSignature> getSignatures() {
        return signatures;
    }

    public Set<Long> getSignatureKeyIDs() {
        return signatureKeyIds;
    }

    public boolean isSigned() {
        return !signatureKeyIds.isEmpty();
    }

    public Map<OpenPgpV4Fingerprint, PGPSignature> getVerifiedSignatures() {
        return verifiedSignatures;
    }

    public Set<OpenPgpV4Fingerprint> getVerifiedSignatureKeyFingerprints() {
        return verifiedSignaturesFingerprints;
    }

    public boolean isVerified() {
        return !verifiedSignaturesFingerprints.isEmpty();
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
        return verifiedSignaturesFingerprints.contains(fingerprint);
    }

    public static Builder getBuilder() {
        return new Builder();
    }

    public static class Builder {

        private final Set<Long> recipientFingerprints = new HashSet<>();
        private OpenPgpV4Fingerprint decryptionFingerprint;
        private final Set<PGPSignature> signatures = new HashSet<>();
        private final Set<Long> signatureKeyIds = new HashSet<>();
        private final Map<OpenPgpV4Fingerprint, PGPSignature> verifiedSignatures = new ConcurrentHashMap<>();
        private final Set<OpenPgpV4Fingerprint> verifiedSignatureKeyFingerprints = new HashSet<>();
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

        public Builder addSignature(PGPSignature signature) {
            signatures.add(signature);
            return this;
        }

        public Builder addUnverifiedSignatureKeyId(Long keyId) {
            this.signatureKeyIds.add(keyId);
            return this;
        }

        public Builder putVerifiedSignature(OpenPgpV4Fingerprint fingerprint, PGPSignature verifiedSignature) {
            verifiedSignatures.put(fingerprint, verifiedSignature);
            return this;
        }

        public Builder addVerifiedSignatureFingerprint(OpenPgpV4Fingerprint fingerprint) {
            this.verifiedSignatureKeyFingerprints.add(fingerprint);
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

        public OpenPgpMetadata build() {
            return new OpenPgpMetadata(recipientFingerprints, decryptionFingerprint,
                    symmetricKeyAlgorithm, compressionAlgorithm, integrityProtected,
                    signatures, signatureKeyIds,
                    verifiedSignatures, verifiedSignatureKeyFingerprints);
        }
    }
}
