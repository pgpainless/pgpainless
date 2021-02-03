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
package org.pgpainless.key.modification.secretkeyring;

import static org.pgpainless.key.util.KeyRingUtils.unlockSecretKey;
import static org.pgpainless.util.CollectionUtils.iteratorToList;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
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
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PassphraseMapKeyRingProtector;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.key.util.SignatureUtils;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.SignatureSubpacketGeneratorUtil;
import org.pgpainless.util.selection.userid.SelectUserId;

public class SecretKeyRingEditor implements SecretKeyRingEditorInterface {

    // Default algorithm for calculating private key checksums
    // While I'd like to use something else, eg. SHA256, BC seems to lack support for
    // calculating secret key checksums with algorithms other than SHA1.
    private final HashAlgorithm defaultDigestHashAlgorithm = HashAlgorithm.SHA1;

    private PGPSecretKeyRing secretKeyRing;

    public SecretKeyRingEditor(PGPSecretKeyRing secretKeyRing) {
        if (secretKeyRing == null) {
            throw new NullPointerException("SecretKeyRing MUST NOT be null.");
        }
        this.secretKeyRing = secretKeyRing;
    }

    @Override
    public SecretKeyRingEditorInterface addUserId(String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException {
        return addUserId(secretKeyRing.getPublicKey().getKeyID(), userId, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface addUserId(long keyId, String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException {
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
    public SecretKeyRingEditorInterface deleteUserId(String userId, SecretKeyRingProtector protector) {
        PGPPublicKey publicKey = secretKeyRing.getPublicKey();
        return deleteUserId(publicKey.getKeyID(), userId, protector);
    }

    @Override
    public SecretKeyRingEditorInterface deleteUserIds(SelectUserId selectionStrategy, SecretKeyRingProtector secretKeyRingProtector) {
        PGPPublicKey publicKey = secretKeyRing.getPublicKey();
        return deleteUserIds(publicKey.getKeyID(), selectionStrategy, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface deleteUserIds(long keyId, SelectUserId selectionStrategy, SecretKeyRingProtector secretKeyRingProtector) {
        List<PGPPublicKey> publicKeys = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeyRing.getPublicKeys();
        boolean foundKey = false;
        while (publicKeyIterator.hasNext()) {
            PGPPublicKey publicKey = publicKeyIterator.next();
            if (publicKey.getKeyID() == keyId) {
                foundKey = true;
                List<String> matchingUserIds = selectionStrategy.selectUserIds(iteratorToList(publicKey.getUserIDs()));
                if (matchingUserIds.isEmpty()) {
                    throw new NoSuchElementException("Key " + Long.toHexString(keyId) + " does not have a matching user-id attribute.");
                }
                for (String userId : matchingUserIds) {
                    publicKey = PGPPublicKey.removeCertification(publicKey, userId);
                }
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
    public SecretKeyRingEditorInterface addSubKey(@Nonnull KeySpec keySpec,
                                                  @Nonnull Passphrase subKeyPassphrase,
                                                  SecretKeyRingProtector secretKeyRingProtector)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {

        PGPSecretKey secretSubKey = generateSubKey(keySpec, subKeyPassphrase);
        SecretKeyRingProtector subKeyProtector = PasswordBasedSecretKeyRingProtector
                .forKey(secretSubKey, subKeyPassphrase);

        return addSubKey(secretSubKey, subKeyProtector, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(PGPSecretKey secretSubKey,
                                                  SecretKeyRingProtector subKeyProtector,
                                                  SecretKeyRingProtector keyRingProtector)
            throws PGPException {

        PGPPublicKey primaryKey = secretKeyRing.getSecretKey().getPublicKey();

        PBESecretKeyDecryptor ringDecryptor = keyRingProtector.getDecryptor(primaryKey.getKeyID());
        PBESecretKeyEncryptor subKeyEncryptor = subKeyProtector.getEncryptor(secretSubKey.getKeyID());

        PGPDigestCalculator digestCalculator =
                ImplementationFactory.getInstance().getPGPDigestCalculator(defaultDigestHashAlgorithm);
        PGPContentSignerBuilder contentSignerBuilder = ImplementationFactory.getInstance()
                .getPGPContentSignerBuilder(
                        primaryKey.getAlgorithm(),
                        HashAlgorithm.SHA256.getAlgorithmId() // TODO: Why SHA256?
                );

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
        PGPDigestCalculator checksumCalculator = ImplementationFactory.getInstance()
                .getPGPDigestCalculator(defaultDigestHashAlgorithm);

        PBESecretKeyEncryptor subKeyEncryptor = subKeyPassphrase.isEmpty() ? null :
                ImplementationFactory.getInstance().getPBESecretKeyEncryptor(SymmetricKeyAlgorithm.AES_256, subKeyPassphrase);

        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(keySpec);
        PGPSecretKey secretKey = new PGPSecretKey(keyPair.getPrivateKey(), keyPair.getPublicKey(),
                checksumCalculator, false, subKeyEncryptor);
        return secretKey;
    }

    @Override
    public SecretKeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint,
                                                     SecretKeyRingProtector protector) {
        return deleteSubKey(fingerprint.getKeyId(), protector);
    }

    @Override
    public SecretKeyRingEditorInterface deleteSubKey(long subKeyId,
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
    public SecretKeyRingEditorInterface revoke(SecretKeyRingProtector secretKeyRingProtector,
                                               RevocationAttributes revocationAttributes)
            throws PGPException {
        return revokeSubKey(secretKeyRing.getSecretKey().getKeyID(), secretKeyRingProtector, revocationAttributes);
    }

    @Override
    public SecretKeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint,
                                                     SecretKeyRingProtector protector,
                                                     RevocationAttributes revocationAttributes)
            throws PGPException {
        return revokeSubKey(fingerprint.getKeyId(), protector, revocationAttributes);
    }

    @Override
    public SecretKeyRingEditorInterface revokeSubKey(long subKeyId,
                                                     SecretKeyRingProtector protector,
                                                     RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubKey = secretKeyRing.getPublicKey(subKeyId);
        if (revokeeSubKey == null) {
            throw new NoSuchElementException("No subkey with id " + Long.toHexString(subKeyId) + " found.");
        }

        secretKeyRing = revokeSubKey(protector, revokeeSubKey, revocationAttributes);
        return this;
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserIdOnAllSubkeys(String userId,
                                                                 SecretKeyRingProtector secretKeyRingProtector,
                                                                 RevocationAttributes revocationAttributes)
            throws PGPException {
        Iterator<PGPPublicKey> iterator = secretKeyRing.getPublicKeys();
        while (iterator.hasNext()) {
            PGPPublicKey publicKey = iterator.next();
            try {
                revokeUserId(userId, new OpenPgpV4Fingerprint(publicKey), secretKeyRingProtector, revocationAttributes);
            } catch (IllegalArgumentException | NoSuchElementException e) {
                // skip
            }
        }
        return this;
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserId(String userId,
                                                     OpenPgpV4Fingerprint subkeyFingerprint,
                                                     SecretKeyRingProtector secretKeyRingProtector,
                                                     RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey publicKey = secretKeyRing.getPublicKey(subkeyFingerprint.getKeyId());
        if (publicKey == null) {
            throw new IllegalArgumentException("Key ring does not carry a public key with fingerprint " + subkeyFingerprint);
        }

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        if (!info.getUserIds().contains(userId)) {
            throw new NoSuchElementException("Key " + subkeyFingerprint + " does not carry userID '" + userId + '\'');
        }

        return doRevokeUserId(userId, subkeyFingerprint.getKeyId(), secretKeyRingProtector, revocationAttributes);
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserId(String userId,
                                                     long subkeyId,
                                                     SecretKeyRingProtector secretKeyRingProtector,
                                                     RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey publicKey = secretKeyRing.getPublicKey(subkeyId);
        if (publicKey == null) {
            throw new IllegalArgumentException("Key ring does not carry a public key with ID " + Long.toHexString(subkeyId));
        }

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        if (!info.getUserIds().contains(userId)) {
            throw new NoSuchElementException("Key " + Long.toHexString(subkeyId) + " does not carry userID '" + userId + '\'');
        }

        return doRevokeUserId(userId, subkeyId, secretKeyRingProtector, revocationAttributes);
    }

    private SecretKeyRingEditorInterface doRevokeUserId(String userId,
                                                        long subKeyId,
                                                        SecretKeyRingProtector protector,
                                                        RevocationAttributes revocationAttributes) throws PGPException {
        PGPPublicKey publicKey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, subKeyId);
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        PGPPrivateKey privateKey = unlockSecretKey(primaryKey, protector);

        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setSignatureCreationTime(false, new Date());
        subpacketGenerator.setRevocable(false, false);
        subpacketGenerator.setIssuerFingerprint(false, primaryKey);
        if (revocationAttributes != null) {
            RevocationAttributes.Reason reason = revocationAttributes.getReason();
            if (reason != RevocationAttributes.Reason.NO_REASON
                    && reason != RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID) {
                throw new IllegalArgumentException("Revocation reason must either be NO_REASON or USER_ID_NO_LONGER_VALID");
            }
            subpacketGenerator.setRevocationReason(false, revocationAttributes.getReason().code(), revocationAttributes.getDescription());
        }

        PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignatureGeneratorFor(primaryKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
        signatureGenerator.init(SignatureType.CERTIFICATION_REVOCATION.getCode(), privateKey);

        PGPSignature revocationSignature = signatureGenerator.generateCertification(userId, publicKey);
        publicKey = PGPPublicKey.addCertification(publicKey, userId, revocationSignature);

        PGPPublicKeyRing publicKeyRing = KeyRingUtils.publicKeyRingFrom(secretKeyRing);
        publicKeyRing = PGPPublicKeyRing.insertPublicKey(publicKeyRing, publicKey);
        secretKeyRing =  PGPSecretKeyRing.replacePublicKeys(secretKeyRing, publicKeyRing);

        return this;
    }

    @Override
    public SecretKeyRingEditorInterface setExpirationDate(Date expiration,
                                                          SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return setExpirationDate(new OpenPgpV4Fingerprint(secretKeyRing), expiration, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface setExpirationDate(OpenPgpV4Fingerprint fingerprint,
                                                          Date expiration,
                                                          SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {

        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        if (!primaryKey.isMasterKey()) {
            throw new IllegalArgumentException("Key Ring does not appear to contain a primary secret key.");
        }

        boolean found = false;
        Iterator<PGPSecretKey> iterator = secretKeyRing.iterator();
        while (iterator.hasNext()) {
            PGPSecretKey secretKey = iterator.next();

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

        PGPPrivateKey privateKey = KeyRingUtils.unlockSecretKey(primaryKey, secretKeyRingProtector);
        PGPPublicKey subjectPubKey = subjectKey.getPublicKey();

        PGPSignature oldSignature = getPreviousSignature(primaryKey, subjectPubKey);

        PGPSignatureSubpacketVector oldSubpackets = oldSignature.getHashedSubPackets();
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator(oldSubpackets);
        SignatureSubpacketGeneratorUtil.setSignatureCreationTimeInSubpacketGenerator(new Date(), subpacketGenerator);
        SignatureSubpacketGeneratorUtil.setExpirationDateInSubpacketGenerator(expiration, subjectPubKey.getCreationTime(), subpacketGenerator);

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

            PGPSignature signature = signatureGenerator.generateCertification(primaryKey.getPublicKey(), subjectPubKey);
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
                if (next.getSignatureType() == PGPSignature.POSITIVE_CERTIFICATION) {
                    oldSignature = next;
                }
            }
            if (oldSignature == null) {
                throw new IllegalStateException("Key " + new OpenPgpV4Fingerprint(subjectPubKey) + " does not have a previous positive signature.");
            }
        } else {
            Iterator bindingSignatures = subjectPubKey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
            while (bindingSignatures.hasNext()) {
                oldSignature = (PGPSignature) bindingSignatures.next();
            }
        }

        if (oldSignature == null) {
            throw new IllegalStateException("Key " + new OpenPgpV4Fingerprint(subjectPubKey) + " does not have a previous subkey binding signature.");
        }
        return oldSignature;
    }



    @Override
    public PGPSignature createRevocationCertificate(OpenPgpV4Fingerprint fingerprint,
                                                    SecretKeyRingProtector secretKeyRingProtector,
                                                    RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubKey = secretKeyRing.getPublicKey(fingerprint.getKeyId());
        if (revokeeSubKey == null) {
            throw new NoSuchElementException("No subkey with fingerprint " + fingerprint + " found.");
        }

        PGPSignature revocationCertificate = generateRevocation(secretKeyRingProtector, revokeeSubKey, revocationAttributes);
        return revocationCertificate;
    }

    @Override
    public PGPSignature createRevocationCertificate(long subKeyId,
                                                    SecretKeyRingProtector secretKeyRingProtector,
                                                    RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubKey = secretKeyRing.getPublicKey(subKeyId);
        if (revokeeSubKey == null) {
            throw new NoSuchElementException("No subkey with id " + Long.toHexString(subKeyId) + " found.");
        }

        PGPSignature revocationCertificate = generateRevocation(secretKeyRingProtector, revokeeSubKey, revocationAttributes);
        return revocationCertificate;
    }

    private PGPSecretKeyRing revokeSubKey(SecretKeyRingProtector protector,
                                          PGPPublicKey revokeeSubKey,
                                          RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPSignature subKeyRevocation = generateRevocation(protector, revokeeSubKey, revocationAttributes);
        revokeeSubKey = PGPPublicKey.addCertification(revokeeSubKey, subKeyRevocation);

        // Inject revoked public key into key ring
        PGPPublicKeyRing publicKeyRing = KeyRingUtils.publicKeyRingFrom(secretKeyRing);
        publicKeyRing = PGPPublicKeyRing.insertPublicKey(publicKeyRing, revokeeSubKey);
        return PGPSecretKeyRing.replacePublicKeys(secretKeyRing, publicKeyRing);
    }

    private PGPSignature generateRevocation(SecretKeyRingProtector protector,
                                            PGPPublicKey revokeeSubKey,
                                            RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignatureGeneratorFor(primaryKey);
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setIssuerFingerprint(false, primaryKey);

        if (revocationAttributes != null) {
            subpacketGenerator.setRevocationReason(false, revocationAttributes.getReason().code(), revocationAttributes.getDescription());
        }

        PGPSignatureSubpacketVector subPackets = subpacketGenerator.generate();
        signatureGenerator.setHashedSubpackets(subPackets);

        PGPPrivateKey privateKey = primaryKey.extractPrivateKey(protector.getDecryptor(primaryKey.getKeyID()));
        SignatureType type = revokeeSubKey.isMasterKey() ? SignatureType.KEY_REVOCATION : SignatureType.SUBKEY_REVOCATION;
        signatureGenerator.init(type.getCode(), privateKey);

        // Generate revocation
        PGPSignature subKeyRevocation = signatureGenerator.generateCertification(primaryKey.getPublicKey(), revokeeSubKey);
        return subKeyRevocation;
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
        public SecretKeyRingEditorInterface toNewPassphrase(Passphrase passphrase) throws PGPException {
            SecretKeyRingProtector newProtector = new PasswordBasedSecretKeyRingProtector(
                    newProtectionSettings, new SolitaryPassphraseProvider(passphrase));

            PGPSecretKeyRing secretKeys = changePassphrase(keyId, SecretKeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            SecretKeyRingEditor.this.secretKeyRing = secretKeys;

            return SecretKeyRingEditor.this;
        }

        @Override
        public SecretKeyRingEditorInterface toNoPassphrase() throws PGPException {
            SecretKeyRingProtector newProtector = new UnprotectedKeysProtector();

            PGPSecretKeyRing secretKeys = changePassphrase(keyId, SecretKeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            SecretKeyRingEditor.this.secretKeyRing = secretKeys;

            return SecretKeyRingEditor.this;
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
        PGPDigestCalculator checksumCalculator = ImplementationFactory.getInstance()
                .getPGPDigestCalculator(defaultDigestHashAlgorithm);
        PBESecretKeyEncryptor encryptor = protector.getEncryptor(publicKey.getKeyID());
        PGPSecretKey secretKey = new PGPSecretKey(privateKey, publicKey, checksumCalculator, publicKey.isMasterKey(), encryptor);
        return secretKey;
    }
}
