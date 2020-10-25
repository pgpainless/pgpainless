/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.modification;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;
import org.pgpainless.util.Passphrase;

public class KeyRingEditor implements KeyRingEditorInterface {

    private PGPSecretKeyRing secretKeyRing;

    public KeyRingEditor(PGPSecretKeyRing secretKeyRing) {
        if (secretKeyRing == null) {
            throw new NullPointerException("SecretKeyRing MUST NOT be null.");
        }
        this.secretKeyRing = secretKeyRing;
    }

    @Override
    public KeyRingEditorInterface addUserId(String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException {
        userId = sanitizeUserId(userId);

        Iterator<PGPSecretKey> secretKeys = secretKeyRing.getSecretKeys();
        PGPSecretKey primarySecKey = secretKeys.next();
        PGPPublicKey primaryPubKey = secretKeyRing.getPublicKey();

        PGPPrivateKey privateKey = unlockSecretKey(primarySecKey, secretKeyRingProtector);

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                getPgpContentSignerBuilderForKey(primarySecKey));
        signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.getCode(), privateKey);
        PGPSignature userIdSignature = signatureGenerator.generateCertification(userId, primaryPubKey);
        primaryPubKey = PGPPublicKey.addCertification(primaryPubKey,
                userId, userIdSignature);

        PGPDigestCalculator digestCalculator = new BcPGPDigestCalculatorProvider().get(
                // TODO: Is SHA1 still a good choice?
                //  If not, what to use/how to make a proper choice?
                HashAlgorithm.SHA1.getAlgorithmId());

        // "reassemble" secret key ring with modified primary key
        primarySecKey = new PGPSecretKey(privateKey, primaryPubKey, digestCalculator, true,
                secretKeyRingProtector.getEncryptor(primaryPubKey.getKeyID()));
        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        secretKeyList.add(primarySecKey);
        while (secretKeys.hasNext()) {
            secretKeyList.add(secretKeys.next());
        }
        secretKeyRing = new PGPSecretKeyRing(secretKeyList);

        return this;
    }

    private static BcPGPContentSignerBuilder getPgpContentSignerBuilderForKey(PGPSecretKey secretKey) {
        List<HashAlgorithm> preferredHashAlgorithms = OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(secretKey.getPublicKey());
        HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(preferredHashAlgorithms);

        return new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), hashAlgorithm.getAlgorithmId());
    }

    private static HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms) {
        // TODO: Match our list of supported hash algorithms against the list, to determine the best suitable algo.
        //  For now we just take the first algorithm in the list and hope that BC has support for it.
        return preferredHashAlgorithms.get(0);
    }

    private PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector protector) throws PGPException {
        PBESecretKeyDecryptor secretKeyDecryptor = protector.getDecryptor(secretKey.getKeyID());
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(secretKeyDecryptor);
        return privateKey;
    }

    private String sanitizeUserId(String userId) {
        userId = userId.trim();
        // TODO: Further research how to sanitize user IDs.
        //  eg. what about newlines?
        return userId;
    }

    @Override
    public KeyRingEditorInterface deleteUserId(String userId, SecretKeyRingProtector protector) {
        return this;
    }

    @Override
    public KeyRingEditorInterface addSubKey(KeySpec keySpec, SecretKeyRingProtector protector) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint, SecretKeyRingProtector protector) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(long subKeyId, SecretKeyRingProtector protector) {
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint, SecretKeyRingProtector protector) {
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(long subKeyId, SecretKeyRingProtector protector) {
        return this;
    }

    @Override
    public WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(@Nullable Passphrase oldPassphrase,
                                                                           @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        return new WithKeyRingEncryptionSettingsImpl();
    }

    @Override
    public WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(@Nonnull Long keyId,
                                                                                 @Nullable Passphrase oldPassphrase,
                                                                                 @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        return new WithKeyRingEncryptionSettingsImpl();
    }

    @Override
    public PGPSecretKeyRing done() {
        return secretKeyRing;
    }

    private class WithKeyRingEncryptionSettingsImpl implements WithKeyRingEncryptionSettings {

        @Override
        public WithPassphrase withSecureDefaultSettings() {
            return withCustomSettings(KeyRingProtectionSettings.secureDefaultSettings());
        }

        @Override
        public WithPassphrase withCustomSettings(KeyRingProtectionSettings settings) {
            return new WithPassphraseImpl();
        }
    }

    private class WithPassphraseImpl implements WithPassphrase {

        @Override
        public KeyRingEditorInterface toNewPassphrase(Passphrase passphrase) {
            return KeyRingEditor.this;
        }

        @Override
        public KeyRingEditorInterface noPassphrase() {
            return KeyRingEditor.this;
        }
    }
}
