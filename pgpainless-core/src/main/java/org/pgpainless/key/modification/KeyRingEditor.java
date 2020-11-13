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

import static org.pgpainless.key.util.KeyUtils.unlockSecretKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PassphraseMapKeyRingProtector;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.SignatureUtils;
import org.pgpainless.util.NotYetImplementedException;
import org.pgpainless.util.Passphrase;

public class KeyRingEditor implements KeyRingEditorInterface {

    // Default algorithm for calculating private key checksums
    // While I'd like to use something else, eg. SHA256, BC seems to lack support for
    // calculating secret key checksums with algorithms other than SHA1.
    private final HashAlgorithm defaultDigestHashAlgorithm = HashAlgorithm.SHA1;

    private PGPSecretKeyRing secretKeyRing;

    public KeyRingEditor(PGPSecretKeyRing secretKeyRing) {
        if (secretKeyRing == null) {
            throw new NullPointerException("SecretKeyRing MUST NOT be null.");
        }
        this.secretKeyRing = secretKeyRing;
    }

    @Override
    public KeyRingEditorInterface addUserId(String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException {
        return addUserId(secretKeyRing.getPublicKey().getKeyID(), userId, secretKeyRingProtector);
    }

    @Override
    public KeyRingEditorInterface addUserId(long keyId, String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException {
        userId = sanitizeUserId(userId);

        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        Iterator<PGPSecretKey> secretKeyIterator = secretKeyRing.getSecretKeys();

        boolean found = false;
        while (!found && secretKeyIterator.hasNext()) {
            PGPSecretKey secretKey = secretKeyIterator.next();
            if (secretKey.getKeyID() == keyId) {
                found = true;
                PGPPublicKey publicKey = secretKey.getPublicKey();
                PGPPrivateKey privateKey = unlockSecretKey(secretKey, secretKeyRingProtector);
                publicKey = addUserIdToPubKey(userId, privateKey, publicKey);
                secretKey = PGPSecretKey.replacePublicKey(secretKey, publicKey);
            }
            secretKeyList.add(secretKey);
        }

        if (!found) {
            throw new NoSuchElementException("Cannot find secret key with id " + Long.toHexString(keyId));
        }

        secretKeyRing = new PGPSecretKeyRing(secretKeyList);

        return this;
    }

    private static PGPPublicKey addUserIdToPubKey(String userId, PGPPrivateKey privateKey, PGPPublicKey publicKey) throws PGPException {
        if (privateKey.getKeyID() != publicKey.getKeyID()) {
            throw new IllegalArgumentException("Key-ID mismatch!");
        }
        // Create signature with new user-id and add it to the public key
        PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignatureGeneratorFor(publicKey);
        signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.getCode(), privateKey);

        PGPSignature userIdSignature = signatureGenerator.generateCertification(userId, publicKey);
        publicKey = PGPPublicKey.addCertification(publicKey,
                userId, userIdSignature);

        return publicKey;
    }

    // TODO: Move to utility class?
    private String sanitizeUserId(String userId) {
        userId = userId.trim();
        // TODO: Further research how to sanitize user IDs.
        //  eg. what about newlines?
        return userId;
    }

    @Override
    public KeyRingEditorInterface deleteUserId(String userId, SecretKeyRingProtector protector) {
        PGPPublicKey publicKey = secretKeyRing.getPublicKey();
        return deleteUserId(publicKey.getKeyID(), userId, protector);
    }

    @Override
    public KeyRingEditorInterface deleteUserId(long keyId, String userId, SecretKeyRingProtector secretKeyRingProtector) {
        List<PGPPublicKey> publicKeys = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeyRing.getPublicKeys();
        boolean foundKey = false;
        while (publicKeyIterator.hasNext()) {
            PGPPublicKey publicKey = publicKeyIterator.next();
            if (publicKey.getKeyID() == keyId) {
                foundKey = true;
                if (!hasUserId(userId, publicKey)) {
                    throw new NoSuchElementException("Key " + Long.toHexString(keyId) + " does not have a user-id attribute of value '" + userId + "'");
                }
                publicKey = PGPPublicKey.removeCertification(publicKey, userId);
            }
            publicKeys.add(publicKey);
        }
        if (!foundKey) {
            throw new NoSuchElementException("Cannot find public key with id " + Long.toHexString(keyId));
        }
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeys);
        secretKeyRing = PGPSecretKeyRing.replacePublicKeys(secretKeyRing, publicKeyRing);
        return this;
    }

    private static boolean hasUserId(String userId, PGPPublicKey publicKey) {
        boolean hasUserId = false;
        Iterator<String> userIdIterator = publicKey.getUserIDs();
        while (userIdIterator.hasNext()) {
            hasUserId = userId.equals(userIdIterator.next());
            if (hasUserId) break;
        }
        return hasUserId;
    }

    @Override
    public KeyRingEditorInterface addSubKey(@Nonnull KeySpec keySpec,
                                            @Nonnull Passphrase subKeyPassphrase,
                                            SecretKeyRingProtector secretKeyRingProtector)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {

        PGPSecretKey secretSubKey = generateSubKey(keySpec, subKeyPassphrase);
        SecretKeyRingProtector subKeyProtector = PasswordBasedSecretKeyRingProtector
                .forKey(secretSubKey, subKeyPassphrase);

        return addSubKey(secretSubKey, subKeyProtector, secretKeyRingProtector);
    }

    @Override
    public KeyRingEditorInterface addSubKey(PGPSecretKey secretSubKey,
                                            SecretKeyRingProtector subKeyProtector,
                                            SecretKeyRingProtector keyRingProtector)
            throws PGPException {

        PGPPublicKey primaryKey = secretKeyRing.getSecretKey().getPublicKey();

        PBESecretKeyDecryptor ringDecryptor = keyRingProtector.getDecryptor(primaryKey.getKeyID());
        PBESecretKeyEncryptor subKeyEncryptor = subKeyProtector.getEncryptor(secretSubKey.getKeyID());

        PGPDigestCalculator digestCalculator = new BcPGPDigestCalculatorProvider()
                .get(defaultDigestHashAlgorithm.getAlgorithmId());
        PGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(
                primaryKey.getAlgorithm(), HashAlgorithm.SHA256.getAlgorithmId());

        PGPPrivateKey privateSubKey = unlockSecretKey(secretSubKey, subKeyProtector);
        PGPKeyPair subKeyPair = new PGPKeyPair(secretSubKey.getPublicKey(), privateSubKey);

        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
                secretKeyRing, ringDecryptor, digestCalculator, contentSignerBuilder, subKeyEncryptor);

        keyRingGenerator.addSubKey(subKeyPair);
        secretKeyRing = keyRingGenerator.generateSecretKeyRing();

        return this;
    }

    private PGPSecretKey generateSubKey(@Nonnull KeySpec keySpec,
                                        @Nonnull Passphrase subKeyPassphrase)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPDigestCalculator checksumCalculator = new BcPGPDigestCalculatorProvider()
                .get(defaultDigestHashAlgorithm.getAlgorithmId());

        PBESecretKeyEncryptor subKeyEncryptor = subKeyPassphrase.isEmpty() ? null :
                new BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithm.AES_256.getAlgorithmId())
                        .build(subKeyPassphrase.getChars());

        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(keySpec);
        PGPSecretKey secretKey = new PGPSecretKey(keyPair.getPrivateKey(), keyPair.getPublicKey(),
                checksumCalculator, false, subKeyEncryptor);
        return secretKey;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint,
                                               SecretKeyRingProtector protector) {
        return deleteSubKey(fingerprint.getKeyId(), protector);
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(long subKeyId,
                                               SecretKeyRingProtector protector) {
        if (secretKeyRing.getSecretKey().getKeyID() == subKeyId) {
            throw new IllegalArgumentException("You cannot delete the primary key of this key ring.");
        }

        PGPSecretKey deleteMe = secretKeyRing.getSecretKey(subKeyId);
        if (deleteMe == null) {
            throw new NoSuchElementException("KeyRing does not contain a key with keyId " + Long.toHexString(subKeyId));
        }

        PGPSecretKeyRing newKeyRing = PGPSecretKeyRing.removeSecretKey(secretKeyRing, deleteMe);
        secretKeyRing = newKeyRing;
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint, SecretKeyRingProtector protector)
            throws PGPException {
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        PGPPrivateKey privateKey = primaryKey.extractPrivateKey(protector.getDecryptor(primaryKey.getKeyID()));

        PGPPublicKey revokeeSubKey = secretKeyRing.getPublicKey(fingerprint.getKeyId());
        if (revokeeSubKey == null) {
            throw new NoSuchElementException("No subkey with fingerprint " + fingerprint + " found.");
        }

        PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignatureGeneratorFor(primaryKey);
        signatureGenerator.init(SignatureType.SUBKEY_REVOCATION.getCode(), privateKey);

        // Generate revocation
        PGPSignature subKeyRevocation = signatureGenerator.generateCertification(primaryKey.getPublicKey(), revokeeSubKey);
        revokeeSubKey = PGPPublicKey.addCertification(revokeeSubKey, subKeyRevocation);

        // Inject revoked public key into key ring
        PGPPublicKeyRing publicKeyRing = KeyRingUtils.publicKeyRingFrom(secretKeyRing);
        publicKeyRing = PGPPublicKeyRing.insertPublicKey(publicKeyRing, revokeeSubKey);
        secretKeyRing = PGPSecretKeyRing.replacePublicKeys(secretKeyRing, publicKeyRing);

        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(long subKeyId, SecretKeyRingProtector protector) {
        throw new NotYetImplementedException();
    }

    @Override
    public WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(@Nullable Passphrase oldPassphrase,
                                                                           @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        SecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
                oldProtectionSettings,
                new SolitaryPassphraseProvider(oldPassphrase));

        return new WithKeyRingEncryptionSettingsImpl(null, protector);
    }

    @Override
    public WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(@Nonnull Long keyId,
                                                                                 @Nullable Passphrase oldPassphrase,
                                                                                 @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        Map<Long, Passphrase> passphraseMap = Collections.singletonMap(keyId, oldPassphrase);
        SecretKeyRingProtector protector = new PassphraseMapKeyRingProtector(
                passphraseMap, oldProtectionSettings, null);

        return new WithKeyRingEncryptionSettingsImpl(keyId, protector);
    }

    @Override
    public PGPSecretKeyRing done() {
        return secretKeyRing;
    }

    private final class WithKeyRingEncryptionSettingsImpl implements WithKeyRingEncryptionSettings {

        private final Long keyId;
        // Protector to unlock the key with the old passphrase
        private final SecretKeyRingProtector oldProtector;

        /**
         * Builder for selecting protection settings.
         *
         * If the keyId is null, the whole keyRing will get the same new passphrase.
         *
         * @param keyId id of the subkey whose passphrase will be changed, or null.
         * @param oldProtector protector do unlock the key/ring.
         */
        private WithKeyRingEncryptionSettingsImpl(Long keyId, SecretKeyRingProtector oldProtector) {
            this.keyId = keyId;
            this.oldProtector = oldProtector;
        }

        @Override
        public WithPassphrase withSecureDefaultSettings() {
            return withCustomSettings(KeyRingProtectionSettings.secureDefaultSettings());
        }

        @Override
        public WithPassphrase withCustomSettings(KeyRingProtectionSettings settings) {
            return new WithPassphraseImpl(keyId, oldProtector, settings);
        }
    }

    private final class WithPassphraseImpl implements WithPassphrase {

        private final SecretKeyRingProtector oldProtector;
        private final KeyRingProtectionSettings newProtectionSettings;
        private final Long keyId;

        private WithPassphraseImpl(Long keyId, SecretKeyRingProtector oldProtector, KeyRingProtectionSettings newProtectionSettings) {
            this.keyId = keyId;
            this.oldProtector = oldProtector;
            this.newProtectionSettings = newProtectionSettings;
        }

        @Override
        public KeyRingEditorInterface toNewPassphrase(Passphrase passphrase) throws PGPException {
            SecretKeyRingProtector newProtector = new PasswordBasedSecretKeyRingProtector(
                    newProtectionSettings, new SolitaryPassphraseProvider(passphrase));

            PGPSecretKeyRing secretKeys = changePassphrase(keyId, KeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            KeyRingEditor.this.secretKeyRing = secretKeys;

            return KeyRingEditor.this;
        }

        @Override
        public KeyRingEditorInterface toNoPassphrase() throws PGPException {
            SecretKeyRingProtector newProtector = new UnprotectedKeysProtector();

            PGPSecretKeyRing secretKeys = changePassphrase(keyId, KeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            KeyRingEditor.this.secretKeyRing = secretKeys;

            return KeyRingEditor.this;
        }
    }

    private PGPSecretKeyRing changePassphrase(Long keyId,
                                              PGPSecretKeyRing secretKeys,
                                              SecretKeyRingProtector oldProtector,
                                              SecretKeyRingProtector newProtector) throws PGPException {
        if (keyId == null) {
            // change passphrase of whole key ring
            List<PGPSecretKey> newlyEncryptedSecretKeys = new ArrayList<>();
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.getSecretKeys();
            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secretKey = secretKeyIterator.next();
                PGPPrivateKey privateKey = unlockSecretKey(secretKey, oldProtector);
                secretKey = lockPrivateKey(privateKey, secretKey.getPublicKey(), newProtector);
                newlyEncryptedSecretKeys.add(secretKey);
            }
            return new PGPSecretKeyRing(newlyEncryptedSecretKeys);
        } else {
            // change passphrase of selected subkey only
            List<PGPSecretKey> secretKeyList = new ArrayList<>();
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.getSecretKeys();
            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secretKey = secretKeyIterator.next();

                if (secretKey.getPublicKey().getKeyID() == keyId) {
                    // Re-encrypt only the selected subkey
                    PGPPrivateKey privateKey = unlockSecretKey(secretKey, oldProtector);
                    secretKey = lockPrivateKey(privateKey, secretKey.getPublicKey(), newProtector);
                }

                secretKeyList.add(secretKey);
            }
            return new PGPSecretKeyRing(secretKeyList);
        }
    }

    // TODO: Move to utility class
    private PGPSecretKey lockPrivateKey(PGPPrivateKey privateKey, PGPPublicKey publicKey, SecretKeyRingProtector protector) throws PGPException {
        PGPDigestCalculator checksumCalculator = new BcPGPDigestCalculatorProvider()
                .get(defaultDigestHashAlgorithm.getAlgorithmId());
        PBESecretKeyEncryptor encryptor = protector.getEncryptor(publicKey.getKeyID());
        PGPSecretKey secretKey = new PGPSecretKey(privateKey, publicKey, checksumCalculator, publicKey.isMasterKey(), encryptor);
        return secretKey;
    }
}
