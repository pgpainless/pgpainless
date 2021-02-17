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
import java.util.HashSet;
import java.util.List;
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
    private final List<OnePassSignature> onePassSignatures;
    private final List<DetachedSignature> detachedSignatures;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean integrityProtected;

    public OpenPgpMetadata(Set<Long> recipientKeyIds,
                           OpenPgpV4Fingerprint decryptionFingerprint,
                           SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                           CompressionAlgorithm algorithm,
                           boolean integrityProtected,
                           List<OnePassSignature> onePassSignatures,
                           List<DetachedSignature> detachedSignatures) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionFingerprint = decryptionFingerprint;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.compressionAlgorithm = algorithm;
        this.integrityProtected = integrityProtected;
        this.detachedSignatures = Collections.unmodifiableList(detachedSignatures);
        this.onePassSignatures = Collections.unmodifiableList(onePassSignatures);
    }

    public Set<Long> getRecipientKeyIds() {
        return recipientKeyIds;
    }

    public boolean isEncrypted() {
        return symmetricKeyAlgorithm != SymmetricKeyAlgorithm.NULL && !getRecipientKeyIds().isEmpty();
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

    public Map<OpenPgpV4Fingerprint, PGPSignature> getVerifiedSignatures() {
        Map<OpenPgpV4Fingerprint, PGPSignature> verifiedSignatures = new ConcurrentHashMap<>();
        for (DetachedSignature detachedSignature : detachedSignatures) {
            if (detachedSignature.isVerified()) {
                verifiedSignatures.put(detachedSignature.getFingerprint(), detachedSignature.getSignature());
            }
        }
        for (OnePassSignature onePassSignature : onePassSignatures) {
            if (onePassSignature.isVerified()) {
                verifiedSignatures.put(onePassSignature.getFingerprint(), onePassSignature.getSignature());
            }
        }

        return verifiedSignatures;
    }

    public Set<OpenPgpV4Fingerprint> getVerifiedSignatureKeyFingerprints() {
        return getVerifiedSignatures().keySet();
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
        return getVerifiedSignatureKeyFingerprints().contains(fingerprint);
    }

    public static class Signature {
        protected final PGPSignature signature;
        protected final OpenPgpV4Fingerprint fingerprint;

        public Signature(PGPSignature signature, OpenPgpV4Fingerprint fingerprint) {
            this.signature = signature;
            this.fingerprint = fingerprint;
        }
    }

    public static Builder getBuilder() {
        return new Builder();
    }

    public static class Builder {

        private final Set<Long> recipientFingerprints = new HashSet<>();
        private OpenPgpV4Fingerprint decryptionFingerprint;
        private final List<DetachedSignature> detachedSignatures = new ArrayList<>();
        private final List<OnePassSignature> onePassSignatures = new ArrayList<>();
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

        public List<DetachedSignature> getDetachedSignatures() {
            return detachedSignatures;
        }

        public Builder setSymmetricKeyAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
            this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            return this;
        }

        public Builder setIntegrityProtected(boolean integrityProtected) {
            this.integrityProtected = integrityProtected;
            return this;
        }

        public void addDetachedSignature(DetachedSignature signature) {
            this.detachedSignatures.add(signature);
        }

        public void addOnePassSignature(OnePassSignature onePassSignature) {
            this.onePassSignatures.add(onePassSignature);
        }

        public OpenPgpMetadata build() {
            return new OpenPgpMetadata(recipientFingerprints, decryptionFingerprint,
                    symmetricKeyAlgorithm, compressionAlgorithm, integrityProtected,
                    onePassSignatures, detachedSignatures);
        }
    }
}
