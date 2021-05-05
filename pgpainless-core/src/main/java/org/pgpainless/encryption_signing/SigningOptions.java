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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.exception.KeyValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public final class SigningOptions {

    public static final class SigningMethod {
        private final PGPSignatureGenerator signatureGenerator;
        private final boolean detached;

        private SigningMethod(PGPSignatureGenerator signatureGenerator, boolean detached) {
            this.signatureGenerator = signatureGenerator;
            this.detached = detached;
        }

        public static SigningMethod inlineSignature(PGPSignatureGenerator signatureGenerator) {
            return new SigningMethod(signatureGenerator, false);
        }

        public static SigningMethod detachedSignature(PGPSignatureGenerator signatureGenerator) {
            return new SigningMethod(signatureGenerator, true);
        }

        public boolean isDetached() {
            return detached;
        }

        public PGPSignatureGenerator getSignatureGenerator() {
            return signatureGenerator;
        }
    }

    private Map<SubkeyIdentifier, SigningMethod> signingMethods = new HashMap<>();
    private HashAlgorithm hashAlgorithmOverride;

    public void addInlineSignature(SecretKeyRingProtector secretKeyDecryptor,
                                   PGPSecretKeyRing secretKey,
                                   DocumentSignatureType signatureType)
            throws KeyValidationException {

    }

    public void addInlineSignature(SecretKeyRingProtector secretKeyDecryptor,
                                   PGPSecretKeyRing secretKey,
                                   String userId,
                                   DocumentSignatureType signatureType)
            throws KeyValidationException, PGPException {
        KeyRingInfo keyRingInfo = new KeyRingInfo(secretKey, new Date());
        if (userId != null) {
            if (!keyRingInfo.isUserIdValid(userId)) {
                throw new KeyValidationException(userId, keyRingInfo.getCurrentUserIdCertification(userId), keyRingInfo.getUserIdRevocation(userId));
            }
        }

        PGPPublicKey signingPubKey = keyRingInfo.getSigningSubkey();
        if (signingPubKey == null) {
            throw new AssertionError("Key has no valid signing key.");
        }
        PGPSecretKey signingSecKey = secretKey.getSecretKey(signingPubKey.getKeyID());
        PGPPrivateKey signingSubkey = signingSecKey.extractPrivateKey(secretKeyDecryptor.getDecryptor(signingPubKey.getKeyID()));
        List<HashAlgorithm> hashAlgorithms = keyRingInfo.getPreferredHashAlgorithms(userId, signingPubKey.getKeyID());
        addSigningMethod(secretKey, signingSubkey, hashAlgorithms.get(0), signatureType, false);
    }

    private void addSigningMethod(PGPSecretKeyRing secretKey,
                                  PGPPrivateKey signingSubkey,
                                  HashAlgorithm hashAlgorithm,
                                  DocumentSignatureType signatureType,
                                  boolean detached)
            throws PGPException {
        SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(secretKey, signingSubkey.getKeyID());
        PGPSignatureGenerator generator = createSignatureGenerator(signingSubkey, hashAlgorithm, signatureType);
        SigningMethod signingMethod = detached ? SigningMethod.detachedSignature(generator) : SigningMethod.inlineSignature(generator);
        signingMethods.put(signingKeyIdentifier, signingMethod);
    }

    private PGPSignatureGenerator createSignatureGenerator(PGPPrivateKey privateKey,
                                                           HashAlgorithm hashAlgorithm,
                                                           DocumentSignatureType signatureType)
            throws PGPException {
        int publicKeyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        PGPContentSignerBuilder signerBuilder = ImplementationFactory.getInstance()
                .getPGPContentSignerBuilder(publicKeyAlgorithm, hashAlgorithm.getAlgorithmId());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
        signatureGenerator.init(signatureType.getSignatureType().getCode(), privateKey);

        return signatureGenerator;
    }

    public Map<SubkeyIdentifier, SigningMethod> getSigningMethods() {
        return Collections.unmodifiableMap(signingMethods);
    }

    public SigningOptions overrideHashAlgorithm(HashAlgorithm hashAlgorithmOverride) {
        this.hashAlgorithmOverride = hashAlgorithmOverride;
        return this;
    }

    public HashAlgorithm getHashAlgorithmOverride() {
        return hashAlgorithmOverride;
    }
}
