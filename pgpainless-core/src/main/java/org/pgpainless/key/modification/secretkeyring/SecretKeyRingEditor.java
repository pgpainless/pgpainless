// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring;

import static org.pgpainless.util.CollectionUtils.concat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.CachingSecretKeyRingProtector;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.protection.fixes.S2KUsageFix;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.builder.RevocationSignatureBuilder;
import org.pgpainless.signature.builder.SelfSignatureBuilder;
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketGeneratorUtil;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.util.Passphrase;

public class SecretKeyRingEditor implements SecretKeyRingEditorInterface {

    private PGPSecretKeyRing secretKeyRing;

    public SecretKeyRingEditor(PGPSecretKeyRing secretKeyRing) {
        if (secretKeyRing == null) {
            throw new NullPointerException("SecretKeyRing MUST NOT be null.");
        }
        this.secretKeyRing = secretKeyRing;
    }

    @Override
    public SecretKeyRingEditorInterface addUserId(
            String userId,
            SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return addUserId(userId, null, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface addUserId(
            String userId,
            @Nullable SelfSignatureSubpackets.Callback signatureSubpacketCallback,
            SecretKeyRingProtector protector) throws PGPException {
        userId = sanitizeUserId(userId);

        // user-id certifications live on the primary key
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();

        // retain key flags from previous signature
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        List<KeyFlag> keyFlags = info.getKeyFlagsOf(info.getKeyId());

        Set<HashAlgorithm> hashAlgorithmPreferences;
        Set<SymmetricKeyAlgorithm> symmetricKeyAlgorithmPreferences;
        Set<CompressionAlgorithm> compressionAlgorithmPreferences;
        try {
            hashAlgorithmPreferences = info.getPreferredHashAlgorithms();
            symmetricKeyAlgorithmPreferences = info.getPreferredSymmetricKeyAlgorithms();
            compressionAlgorithmPreferences = info.getPreferredCompressionAlgorithms();
        } catch (IllegalStateException e) {
            // missing user-id sig
            AlgorithmSuite algorithmSuite = AlgorithmSuite.getDefaultAlgorithmSuite();
            hashAlgorithmPreferences = algorithmSuite.getHashAlgorithms();
            symmetricKeyAlgorithmPreferences = algorithmSuite.getSymmetricKeyAlgorithms();
            compressionAlgorithmPreferences = algorithmSuite.getCompressionAlgorithms();
        }

        SelfSignatureBuilder builder = new SelfSignatureBuilder(primaryKey, protector);
        builder.setSignatureType(SignatureType.POSITIVE_CERTIFICATION);

        // Retain signature subpackets of previous signatures
        builder.getHashedSubpackets().setKeyFlags(keyFlags);
        builder.getHashedSubpackets().setPreferredHashAlgorithms(hashAlgorithmPreferences);
        builder.getHashedSubpackets().setPreferredSymmetricKeyAlgorithms(symmetricKeyAlgorithmPreferences);
        builder.getHashedSubpackets().setPreferredCompressionAlgorithms(compressionAlgorithmPreferences);
        builder.getHashedSubpackets().setFeatures(Feature.MODIFICATION_DETECTION);

        builder.applyCallback(signatureSubpacketCallback);

        PGPSignature signature = builder.build(primaryKey.getPublicKey(), userId);
        secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, userId, signature);

        return this;
    }

    // TODO: Move to utility class?
    private String sanitizeUserId(String userId) {
        userId = userId.trim();
        // TODO: Further research how to sanitize user IDs.
        //  eg. what about newlines?
        return userId;
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(
            @Nonnull KeySpec keySpec,
            @Nonnull Passphrase subKeyPassphrase,
            SecretKeyRingProtector secretKeyRingProtector)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {

        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(keySpec);

        SecretKeyRingProtector subKeyProtector = PasswordBasedSecretKeyRingProtector
                .forKeyId(keyPair.getKeyID(), subKeyPassphrase);

        SelfSignatureSubpackets.Callback callback = new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                SignatureSubpacketsHelper.applyFrom(keySpec.getSubpackets(), (SignatureSubpackets) hashedSubpackets);
            }
        };

        List<KeyFlag> keyFlags = KeyFlag.fromBitmask(keySpec.getSubpackets().getKeyFlags());
        KeyFlag firstFlag = keyFlags.remove(0);
        KeyFlag[] otherFlags = keyFlags.toArray(new KeyFlag[0]);

        return addSubKey(keyPair, callback, subKeyProtector, secretKeyRingProtector, firstFlag, otherFlags);
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(
            @Nonnull KeySpec keySpec,
            @Nullable Passphrase subkeyPassphrase,
            @Nullable SelfSignatureSubpackets.Callback subpacketsCallback,
            SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(keySpec);

        SecretKeyRingProtector subKeyProtector = PasswordBasedSecretKeyRingProtector
                .forKeyId(keyPair.getKeyID(), subkeyPassphrase);

        List<KeyFlag> keyFlags = KeyFlag.fromBitmask(keySpec.getSubpackets().getKeyFlags());
        KeyFlag firstFlag = keyFlags.remove(0);
        KeyFlag[] otherFlags = keyFlags.toArray(new KeyFlag[0]);

        return addSubKey(keyPair, subpacketsCallback, subKeyProtector, secretKeyRingProtector, firstFlag, otherFlags);
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(
            PGPKeyPair subkey,
            @Nullable SelfSignatureSubpackets.Callback bindingSignatureCallback,
            SecretKeyRingProtector subkeyProtector,
            SecretKeyRingProtector primaryKeyProtector,
            KeyFlag keyFlag,
            KeyFlag... additionalKeyFlags)
            throws PGPException, IOException {
        KeyFlag[] flags = concat(keyFlag, additionalKeyFlags);
        PublicKeyAlgorithm subkeyAlgorithm = PublicKeyAlgorithm.fromId(subkey.getPublicKey().getAlgorithm());
        SignatureSubpacketsUtil.assureKeyCanCarryFlags(subkeyAlgorithm);

        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        PublicKeyAlgorithm signingKeyAlgorithm = PublicKeyAlgorithm.fromId(primaryKey.getPublicKey().getAlgorithm());
        HashAlgorithm hashAlgorithm = HashAlgorithmNegotiator
                .negotiateSignatureHashAlgorithm(PGPainless.getPolicy())
                .negotiateHashAlgorithm(info.getPreferredHashAlgorithms());

        // While we'd like to rely on our own BindingSignatureBuilder implementation,
        //  unfortunately we have to use BCs PGPKeyRingGenerator class since there is no public constructor
        //  for subkeys. See https://github.com/bcgit/bc-java/pull/1063
        PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
                secretKeyRing,
                primaryKeyProtector.getDecryptor(primaryKey.getKeyID()),
                ImplementationFactory.getInstance().getV4FingerprintCalculator(),
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        signingKeyAlgorithm, hashAlgorithm),
                subkeyProtector.getEncryptor(subkey.getKeyID()));

        SelfSignatureSubpackets hashedSubpackets = SignatureSubpackets.createHashedSubpackets(primaryKey.getPublicKey());
        SelfSignatureSubpackets unhashedSubpackets = SignatureSubpackets.createEmptySubpackets();
        hashedSubpackets.setKeyFlags(flags);

        if (bindingSignatureCallback != null) {
            bindingSignatureCallback.modifyHashedSubpackets(hashedSubpackets);
            bindingSignatureCallback.modifyUnhashedSubpackets(unhashedSubpackets);
        }

        boolean isSigningKey = CollectionUtils.contains(flags, KeyFlag.SIGN_DATA) ||
                CollectionUtils.contains(flags, KeyFlag.CERTIFY_OTHER);
        PGPContentSignerBuilder primaryKeyBindingSigner = null;
        if (isSigningKey) {
            primaryKeyBindingSigner = ImplementationFactory.getInstance().getPGPContentSignerBuilder(subkeyAlgorithm, hashAlgorithm);
        }

        ringGenerator.addSubKey(subkey,
                SignatureSubpacketsHelper.toVector((SignatureSubpackets) hashedSubpackets),
                SignatureSubpacketsHelper.toVector((SignatureSubpackets) unhashedSubpackets),
                primaryKeyBindingSigner);

        secretKeyRing = ringGenerator.generateSecretKeyRing();

        return this;
    }

    @Override
    public SecretKeyRingEditorInterface revoke(SecretKeyRingProtector secretKeyRingProtector,
                                               @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {
        RevocationSignatureSubpackets.Callback callback = callbackFromRevocationAttributes(revocationAttributes);
        return revoke(secretKeyRingProtector, callback);
    }

    @Override
    public SecretKeyRingEditorInterface revoke(SecretKeyRingProtector secretKeyRingProtector,
                                               @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException {
        return revokeSubKey(secretKeyRing.getSecretKey().getKeyID(), secretKeyRingProtector, subpacketsCallback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeSubKey(long subKeyId,
                                                     SecretKeyRingProtector protector,
                                                     RevocationAttributes revocationAttributes)
            throws PGPException {
        RevocationSignatureSubpackets.Callback callback = callbackFromRevocationAttributes(revocationAttributes);
        return revokeSubKey(subKeyId, protector, callback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeSubKey(long keyID,
                                                     SecretKeyRingProtector secretKeyRingProtector,
                                                     @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException {
        // retrieve subkey to be revoked
        PGPPublicKey revokeeSubKey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, keyID);
        // create revocation
        PGPSignature subKeyRevocation = generateRevocation(secretKeyRingProtector, revokeeSubKey,
                subpacketsCallback);
        // inject revocation sig into key ring
        secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, revokeeSubKey, subKeyRevocation);
        return this;
    }

    @Override
    public PGPSignature createRevocationCertificate(SecretKeyRingProtector secretKeyRingProtector,
                                                    RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubKey = secretKeyRing.getPublicKey();
        PGPSignature revocationCertificate = generateRevocation(
                secretKeyRingProtector, revokeeSubKey, callbackFromRevocationAttributes(revocationAttributes));
        return revocationCertificate;
    }

    @Override
    public PGPSignature createRevocationCertificate(
            long subkeyId,
            SecretKeyRingProtector secretKeyRingProtector,
            RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubkey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, subkeyId);
        RevocationSignatureSubpackets.Callback callback = callbackFromRevocationAttributes(revocationAttributes);
        return generateRevocation(secretKeyRingProtector, revokeeSubkey, callback);
    }

    @Override
    public PGPSignature createRevocationCertificate(
            long subkeyId,
            SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback certificateSubpacketsCallback)
            throws PGPException {
        PGPPublicKey revokeeSubkey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, subkeyId);
        return generateRevocation(secretKeyRingProtector, revokeeSubkey, certificateSubpacketsCallback);
    }

    private PGPSignature generateRevocation(SecretKeyRingProtector protector,
                                            PGPPublicKey revokeeSubKey,
                                            @Nullable RevocationSignatureSubpackets.Callback callback)
            throws PGPException {
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        SignatureType signatureType = revokeeSubKey.isMasterKey() ?
                SignatureType.KEY_REVOCATION : SignatureType.SUBKEY_REVOCATION;

        RevocationSignatureBuilder signatureBuilder =
                new RevocationSignatureBuilder(signatureType, primaryKey, protector);
        signatureBuilder.applyCallback(callback);
        PGPSignature revocation = signatureBuilder.build(revokeeSubKey);
        return revocation;
    }

    private static RevocationSignatureSubpackets.Callback callbackFromRevocationAttributes(
            RevocationAttributes attributes) {
        return new RevocationSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(RevocationSignatureSubpackets hashedSubpackets) {
                if (attributes != null) {
                    hashedSubpackets.setRevocationReason(attributes);
                }
            }
        };
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserId(String userId,
                                                     SecretKeyRingProtector secretKeyRingProtector,
                                                     @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {
        if (revocationAttributes != null) {
            RevocationAttributes.Reason reason = revocationAttributes.getReason();
            if (reason != RevocationAttributes.Reason.NO_REASON
                    && reason != RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID) {
                throw new IllegalArgumentException("Revocation reason must either be NO_REASON or USER_ID_NO_LONGER_VALID");
            }
        }

        RevocationSignatureSubpackets.Callback callback = new RevocationSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(RevocationSignatureSubpackets hashedSubpackets) {
                if (revocationAttributes != null) {
                    hashedSubpackets.setRevocationReason(false, revocationAttributes);
                }
            }
        };

        return revokeUserId(userId, secretKeyRingProtector, callback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserId(
            String userId,
            SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketCallback)
            throws PGPException {
        Iterator<String> userIds = secretKeyRing.getPublicKey().getUserIDs();
        boolean found = false;
        while (userIds.hasNext()) {
            if (userId.equals(userIds.next())) {
                found = true;
                break;
            }
        }
        if (!found) {
            throw new NoSuchElementException("No user-id '" + userId + "' found on the key.");
        }
        return doRevokeUserId(userId, secretKeyRingProtector, subpacketCallback);
    }

    private SecretKeyRingEditorInterface doRevokeUserId(String userId,
                                                        SecretKeyRingProtector protector,
                                                        @Nullable RevocationSignatureSubpackets.Callback callback)
            throws PGPException {
        PGPSecretKey primarySecretKey = secretKeyRing.getSecretKey();
        PGPPublicKey primaryPublicKey = primarySecretKey.getPublicKey();
        RevocationSignatureBuilder signatureBuilder = new RevocationSignatureBuilder(
                SignatureType.CERTIFICATION_REVOCATION,
                primarySecretKey,
                protector);

        signatureBuilder.applyCallback(callback);

        PGPSignature revocationSignature = signatureBuilder.build(userId);
        secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, userId, revocationSignature);
        return this;
    }

    @Override
    public SecretKeyRingEditorInterface setExpirationDate(Date expiration,
                                                          SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return setExpirationDate(OpenPgpFingerprint.of(secretKeyRing), expiration, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface setExpirationDate(OpenPgpFingerprint fingerprint,
                                                          Date expiration,
                                                          SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {

        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        if (!primaryKey.isMasterKey()) {
            throw new IllegalArgumentException("Key Ring does not appear to contain a primary secret key.");
        }

        boolean found = false;
        for (PGPSecretKey secretKey : secretKeyRing) {
            // Skip over unaffected subkeys
            if (secretKey.getKeyID() != fingerprint.getKeyId()) {
                secretKeyList.add(secretKey);
                continue;
            }
            // We found the target subkey
            found = true;
            secretKey = setExpirationDate(primaryKey, secretKey, expiration, secretKeyRingProtector);
            secretKeyList.add(secretKey);
        }

        if (!found) {
            throw new IllegalArgumentException("Key Ring does not contain secret key with fingerprint " + fingerprint);
        }

        secretKeyRing = new PGPSecretKeyRing(secretKeyList);

        return this;
    }

    private PGPSecretKey setExpirationDate(PGPSecretKey primaryKey,
                                           PGPSecretKey subjectKey,
                                           Date expiration,
                                           SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {

        if (expiration != null && expiration.before(subjectKey.getPublicKey().getCreationTime())) {
            throw new IllegalArgumentException("Expiration date cannot be before creation date.");
        }

        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(primaryKey, secretKeyRingProtector);
        PGPPublicKey subjectPubKey = subjectKey.getPublicKey();

        PGPSignature oldSignature = getPreviousSignature(primaryKey, subjectPubKey);

        PGPSignatureSubpacketVector oldSubpackets = oldSignature.getHashedSubPackets();
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator(oldSubpackets);
        SignatureSubpacketGeneratorUtil.setSignatureCreationTimeInSubpacketGenerator(new Date(), subpacketGenerator);
        SignatureSubpacketGeneratorUtil.setKeyExpirationDateInSubpacketGenerator(
                expiration, subjectPubKey.getCreationTime(), subpacketGenerator);

        PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignatureGeneratorFor(primaryKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        if (primaryKey.getKeyID() == subjectKey.getKeyID()) {
            signatureGenerator.init(PGPSignature.POSITIVE_CERTIFICATION, privateKey);

            for (Iterator<String> it = subjectKey.getUserIDs(); it.hasNext(); ) {
                String userId = it.next();
                PGPSignature signature = signatureGenerator.generateCertification(userId, subjectPubKey);
                subjectPubKey = PGPPublicKey.addCertification(subjectPubKey, userId, signature);
            }
        } else {
            signatureGenerator.init(PGPSignature.SUBKEY_BINDING, privateKey);

            PGPSignature signature = signatureGenerator.generateCertification(
                    primaryKey.getPublicKey(), subjectPubKey);
            subjectPubKey = PGPPublicKey.addCertification(subjectPubKey, signature);
        }

        subjectKey = PGPSecretKey.replacePublicKey(subjectKey, subjectPubKey);
        return subjectKey;
    }

    private PGPSignature getPreviousSignature(PGPSecretKey primaryKey, PGPPublicKey subjectPubKey) {
        PGPSignature oldSignature = null;
        if (primaryKey.getKeyID() == subjectPubKey.getKeyID()) {
            Iterator<PGPSignature> keySignatures = subjectPubKey.getSignaturesForKeyID(primaryKey.getKeyID());
            while (keySignatures.hasNext()) {
                PGPSignature next = keySignatures.next();
                SignatureType type = SignatureType.valueOf(next.getSignatureType());
                if (type == SignatureType.POSITIVE_CERTIFICATION ||
                        type == SignatureType.CASUAL_CERTIFICATION ||
                        type == SignatureType.GENERIC_CERTIFICATION) {
                    oldSignature = next;
                }
            }
            if (oldSignature == null) {
                throw new IllegalStateException("Key " + OpenPgpFingerprint.of(subjectPubKey) +
                        " does not have a previous positive/casual/generic certification signature.");
            }
        } else {
            Iterator<PGPSignature> bindingSignatures = subjectPubKey.getSignaturesOfType(
                    SignatureType.SUBKEY_BINDING.getCode());
            while (bindingSignatures.hasNext()) {
                oldSignature = bindingSignatures.next();
            }
        }

        if (oldSignature == null) {
            throw new IllegalStateException("Key " + OpenPgpFingerprint.of(subjectPubKey) +
                    " does not have a previous subkey binding signature.");
        }
        return oldSignature;
    }

    @Override
    public WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(
            @Nullable Passphrase oldPassphrase,
            @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        SecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
                oldProtectionSettings,
                new SolitaryPassphraseProvider(oldPassphrase));

        return new WithKeyRingEncryptionSettingsImpl(null, protector);
    }

    @Override
    public WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(
            @Nonnull Long keyId,
            @Nullable Passphrase oldPassphrase,
            @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        Map<Long, Passphrase> passphraseMap = Collections.singletonMap(keyId, oldPassphrase);
        SecretKeyRingProtector protector = new CachingSecretKeyRingProtector(
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

        private WithPassphraseImpl(
                Long keyId,
                SecretKeyRingProtector oldProtector,
                KeyRingProtectionSettings newProtectionSettings) {
            this.keyId = keyId;
            this.oldProtector = oldProtector;
            this.newProtectionSettings = newProtectionSettings;
        }

        @Override
        public SecretKeyRingEditorInterface toNewPassphrase(Passphrase passphrase)
                throws PGPException {
            SecretKeyRingProtector newProtector = new PasswordBasedSecretKeyRingProtector(
                    newProtectionSettings, new SolitaryPassphraseProvider(passphrase));

            PGPSecretKeyRing secretKeys = changePassphrase(
                    keyId, SecretKeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            SecretKeyRingEditor.this.secretKeyRing = secretKeys;

            return SecretKeyRingEditor.this;
        }

        @Override
        public SecretKeyRingEditorInterface toNoPassphrase()
                throws PGPException {
            SecretKeyRingProtector newProtector = new UnprotectedKeysProtector();

            PGPSecretKeyRing secretKeys = changePassphrase(
                    keyId, SecretKeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            SecretKeyRingEditor.this.secretKeyRing = secretKeys;

            return SecretKeyRingEditor.this;
        }
    }

    private PGPSecretKeyRing changePassphrase(Long keyId,
                                              PGPSecretKeyRing secretKeys,
                                              SecretKeyRingProtector oldProtector,
                                              SecretKeyRingProtector newProtector)
            throws PGPException {
        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        if (keyId == null) {
            // change passphrase of whole key ring
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.getSecretKeys();
            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secretKey = secretKeyIterator.next();
                secretKey = reencryptPrivateKey(secretKey, oldProtector, newProtector);
                secretKeyList.add(secretKey);
            }
        } else {
            // change passphrase of selected subkey only
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.getSecretKeys();
            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secretKey = secretKeyIterator.next();
                if (secretKey.getPublicKey().getKeyID() == keyId) {
                    // Re-encrypt only the selected subkey
                    secretKey = reencryptPrivateKey(secretKey, oldProtector, newProtector);
                }
                secretKeyList.add(secretKey);
            }
        }

        PGPSecretKeyRing newRing = new PGPSecretKeyRing(secretKeyList);
        newRing = s2kUsageFixIfNecessary(newRing, newProtector);
        return newRing;
    }

    private PGPSecretKeyRing s2kUsageFixIfNecessary(PGPSecretKeyRing secretKeys, SecretKeyRingProtector protector)
            throws PGPException {
        boolean hasS2KUsageChecksum = false;
        for (PGPSecretKey secKey : secretKeys) {
            if (secKey.getS2KUsage() == SecretKeyPacket.USAGE_CHECKSUM) {
                hasS2KUsageChecksum = true;
                break;
            }
        }
        if (hasS2KUsageChecksum) {
            secretKeys = S2KUsageFix.replaceUsageChecksumWithUsageSha1(
                    secretKeys, protector, true);
        }
        return secretKeys;
    }

    private static PGPSecretKey reencryptPrivateKey(
            PGPSecretKey secretKey,
            SecretKeyRingProtector oldProtector,
            SecretKeyRingProtector newProtector)
            throws PGPException {
        S2K s2k = secretKey.getS2K();
        // If the key uses GNU_DUMMY_S2K, we leave it as is and skip this block
        if (s2k == null || s2k.getType() != S2K.GNU_DUMMY_S2K) {
            long secretKeyId = secretKey.getKeyID();
            PBESecretKeyDecryptor decryptor = oldProtector.getDecryptor(secretKeyId);
            PBESecretKeyEncryptor encryptor = newProtector.getEncryptor(secretKeyId);
            secretKey = PGPSecretKey.copyWithNewPassword(secretKey, decryptor, encryptor);
        }
        return secretKey;
    }
}
