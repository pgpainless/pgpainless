package org.pgpainless.key.modification;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
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

        PGPPublicKey primaryPubKey = secretKeyRing.getPublicKey();
        PGPPrivateKey privateKey = unlockSecretKey(primaryPubKey.getKeyID(), secretKeyRingProtector);

        signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.getCode(), privateKey);
        PGPSignature userIdSignature = signatureGenerator.generateCertification(userId, primaryPubKey);
        primaryPubKey = PGPPublicKey.addCertification(primaryPubKey,
                userId, userIdSignature);

        // "reassemble" secret key ring with modified primary key
        PGPSecretKey primarySecKey = new PGPSecretKey(
                privateKey,
                primaryPubKey, digestCalculator, true, secretKeyRingProtector);
        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        secretKeyList.add(primarySecKey);
        while (secretKeys.hasNext()) {
            secretKeyList.add(secretKeys.next());
        }
        secretKeyRing = new PGPSecretKeyRing(secretKeyList);

        // extract public key ring from secret keys
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeys = secretKeyRing.getPublicKeys();
        while (publicKeys.hasNext()) {
            publicKeyList.add(publicKeys.next());
        }
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeyList);

        return this;
    }

    private PGPPrivateKey unlockSecretKey(long keyId, SecretKeyRingProtector protector) throws PGPException {
        PGPSecretKey secretKey = secretKeyRing.getSecretKey(keyId);
        PBESecretKeyDecryptor secretKeyDecryptor = protector.getDecryptor(keyId);
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
    public KeyRingEditorInterface deleteUserId(String userId) {
        return this;
    }

    @Override
    public KeyRingEditorInterface addSubKey(KeySpec keySpec) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint) {
        return this;
    }

    @Override
    public KeyRingEditorInterface deleteSubKey(long subKeyId) {
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint) {
        return this;
    }

    @Override
    public KeyRingEditorInterface revokeSubKey(long subKeyId) {
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
