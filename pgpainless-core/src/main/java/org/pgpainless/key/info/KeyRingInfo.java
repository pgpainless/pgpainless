/*
 * Copyright 2020 Paul Schaub. Copyright 2021 Flowcrypt a.s.
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
package org.pgpainless.key.info;

import static org.pgpainless.util.CollectionUtils.iteratorToList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.exception.KeyValidationException;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignaturePicker;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

/**
 * Utility class to quickly extract certain information from a {@link PGPPublicKeyRing}/{@link PGPSecretKeyRing}.
 */
public class KeyRingInfo {

    private static final Pattern PATTERN_EMAIL = Pattern.compile("[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}");

    private final PGPKeyRing keys;
    private Signatures signatures;

    /**
     * Evaluate the key ring at creation time of the given signature.
     *
     * @param keyRing key ring
     * @param signature signature
     * @return info of key ring at signature creation time
     */
    public static KeyRingInfo evaluateForSignature(PGPKeyRing keyRing, PGPSignature signature) {
        return new KeyRingInfo(keyRing, signature.getCreationTime());
    }

    /**
     * Evaluate the key ring right now.
     *
     * @param keys key ring
     */
    public KeyRingInfo(PGPKeyRing keys) {
        this(keys, new Date());
    }

    /**
     * Evaluate the key ring at the provided validation date.
     *
     * @param keys key ring
     * @param validationDate date of validation
     */
    public KeyRingInfo(PGPKeyRing keys, Date validationDate) {
        this.keys = keys;
        this.signatures = new Signatures(keys, validationDate, PGPainless.getPolicy());
    }

    /**
     * Return the first {@link PGPPublicKey} of this key ring.
     *
     * @return public key
     */
    public PGPPublicKey getPublicKey() {
        return keys.getPublicKey();
    }

    /**
     * Return the public key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @return public key or null
     */
    public PGPPublicKey getPublicKey(OpenPgpV4Fingerprint fingerprint) {
        return getPublicKey(fingerprint.getKeyId());
    }

    /**
     * Return the public key with the given key id.
     *
     * @param keyId key id
     * @return public key or null
     */
    public PGPPublicKey getPublicKey(long keyId) {
        return keys.getPublicKey(keyId);
    }

    /**
     * Return the public key with the given key id from the provided key ring.
     *
     * @param keyRing key ring
     * @param keyId key id
     * @return public key or null
     */
    public static PGPPublicKey getPublicKey(PGPKeyRing keyRing, long keyId) {
        return keyRing.getPublicKey(keyId);
    }

    /**
     * Return true if the public key with the given key id is bound to the key ring properly.
     *
     * @param keyId key id
     * @return true if key is bound validly
     */
    public boolean isKeyValidlyBound(long keyId) {
        PGPPublicKey publicKey = keys.getPublicKey(keyId);
        if (publicKey == null) {
            return false;
        }

        if (publicKey == getPublicKey()) {
            return signatures.primaryKeyRevocation == null;
        }

        PGPSignature binding = signatures.subkeyBindings.get(keyId);
        PGPSignature revocation = signatures.subkeyRevocations.get(keyId);
        return binding != null && revocation == null;
    }

    /**
     * Return all {@link PGPPublicKey PGPPublicKeys} of this key ring.
     * The first key in the list being the primary key.
     * Note that the list is unmodifiable.
     *
     * @return list of public keys
     */
    public List<PGPPublicKey> getPublicKeys() {
        Iterator<PGPPublicKey> iterator = keys.getPublicKeys();
        List<PGPPublicKey> list = iteratorToList(iterator);
        return Collections.unmodifiableList(list);
    }

    /**
     * Return the primary {@link PGPSecretKey} of this key ring or null if the key ring is not a {@link PGPSecretKeyRing}.
     *
     * @return primary secret key or null if the key ring is public
     */
    public PGPSecretKey getSecretKey() {
        if (keys instanceof PGPSecretKeyRing) {
            PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) keys;
            return secretKeys.getSecretKey();
        }
        return null;
    }

    /**
     * Return the secret key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @return secret key or null
     */
    public PGPSecretKey getSecretKey(OpenPgpV4Fingerprint fingerprint) {
        return getSecretKey(fingerprint.getKeyId());
    }

    /**
     * Return the secret key with the given key id.
     *
     * @param keyId key id
     * @return secret key or null
     */
    public PGPSecretKey getSecretKey(long keyId) {
        if (keys instanceof PGPSecretKeyRing) {
            return ((PGPSecretKeyRing) keys).getSecretKey(keyId);
        }
        return null;
    }

    /**
     * Return all secret keys of the key ring.
     * If the key ring is a {@link PGPPublicKeyRing}, then return an empty list.
     * Note that the list is unmodifiable.
     *
     * @return list of secret keys
     */
    public List<PGPSecretKey> getSecretKeys() {
        if (keys instanceof PGPSecretKeyRing) {
            PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) keys;
            Iterator<PGPSecretKey> iterator = secretKeys.getSecretKeys();
            return Collections.unmodifiableList(iteratorToList(iterator));
        }
        return Collections.emptyList();
    }

    /**
     * Return the key id of the primary key of this key ring.
     *
     * @return key id
     */
    public long getKeyId() {
        return getPublicKey().getKeyID();
    }

    /**
     * Return the {@link OpenPgpV4Fingerprint} of this key ring.
     *
     * @return fingerprint
     */
    public OpenPgpV4Fingerprint getFingerprint() {
        return new OpenPgpV4Fingerprint(getPublicKey());
    }

    /**
     * Return the primary user-id of the key ring.
     *
     * Note: If no user-id is marked as primary key using a {@link PrimaryUserID} packet, this method returns the
     * first valid user-id, otherwise null.
     *
     * @return primary user-id or null
     */
    public String getPrimaryUserId() {
        String primaryUserId = null;
        Date modificationDate = null;
        for (String userId : getValidUserIds()) {
            PGPSignature signature = signatures.userIdCertifications.get(userId);
            PrimaryUserID subpacket = SignatureSubpacketsUtil.getPrimaryUserId(signature);
            if (subpacket != null && subpacket.isPrimaryUserID()) {
                // if there are multiple primary userIDs, return most recently signed
                if (modificationDate == null || modificationDate.before(signature.getCreationTime())) {
                    primaryUserId = userId;
                    modificationDate = signature.getCreationTime();
                }
            }
        }
        // Workaround for keys with only one user-id but no primary user-id packet.
        if (primaryUserId == null) {
            return getValidUserIds().get(0);
        }

        return primaryUserId;
    }

    /**
     * Return a list of all user-ids of the primary key.
     *
     * @return list of user-ids
     */
    public List<String> getUserIds() {
        Iterator<String> iterator = getPublicKey().getUserIDs();
        List<String> userIds = iteratorToList(iterator);
        return userIds;
    }

    /**
     * Return a list of valid user-ids.
     *
     * @return valid user-ids
     */
    public List<String> getValidUserIds() {
        List<String> valid = new ArrayList<>();
        List<String> userIds = getUserIds();
        for (String userId : userIds) {
            if (isUserIdValid(userId)) {
                valid.add(userId);
            }
        }
        return valid;
    }

    /**
     * Return true if the provided user-id is valid.
     *
     * @param userId user-id
     * @return true if user-id is valid
     */
    public boolean isUserIdValid(String userId) {
        PGPSignature certification = signatures.userIdCertifications.get(userId);
        PGPSignature revocation = signatures.userIdRevocations.get(userId);

        return certification != null && revocation == null;
    }

    /**
     * Return a list of all user-ids of the primary key that appear to be email-addresses.
     *
     * @return email addresses
     */
    public List<String> getEmailAddresses() {
        List<String> userIds = getUserIds();
        List<String> emails = new ArrayList<>();
        for (String userId : userIds) {
            Matcher matcher = PATTERN_EMAIL.matcher(userId);
            if (matcher.find()) {
                emails.add(matcher.group());
            }
        }
        return emails;
    }

    /**
     * Return the current direct-key self signature.
     *
     * @return
     */
    public PGPSignature getCurrentDirectKeySelfSignature() {
        return signatures.primaryKeySelfSignature;
    }

    public PGPSignature getRevocationSelfSignature() {
        return signatures.primaryKeyRevocation;
    }

    public PGPSignature getCurrentUserIdCertification(String userId) {
        return signatures.userIdCertifications.get(userId);
    }

    public PGPSignature getUserIdRevocation(String userId) {
        return signatures.userIdRevocations.get(userId);
    }

    public PGPSignature getCurrentSubkeyBindingSignature(long keyId) {
        return signatures.subkeyBindings.get(keyId);
    }

    public PGPSignature getSubkeyRevocationSignature(long keyId) {
        return signatures.subkeyRevocations.get(keyId);
    }

    public List<KeyFlag> getKeyFlagsOf(long keyId) {
        if (getPublicKey().getKeyID() == keyId) {

            PGPSignature directKeySignature = getCurrentDirectKeySelfSignature();
            if (directKeySignature != null) {
                KeyFlags flags = SignatureSubpacketsUtil.getKeyFlags(directKeySignature);
                if (flags != null) {
                    return KeyFlag.fromBitmask(flags.getFlags());
                }
            }

            String primaryUserId = getPrimaryUserId();
            if (primaryUserId != null) {
                KeyFlags flags = SignatureSubpacketsUtil.getKeyFlags(getCurrentUserIdCertification(primaryUserId));
                if (flags != null) {
                    return KeyFlag.fromBitmask(flags.getFlags());
                }
            }
        } else {
            PGPSignature bindingSignature = getCurrentSubkeyBindingSignature(keyId);
            if (bindingSignature != null) {
                KeyFlags flags = SignatureSubpacketsUtil.getKeyFlags(bindingSignature);
                if (flags != null) {
                    return KeyFlag.fromBitmask(flags.getFlags());
                }
            }
        }
        return Collections.emptyList();
    }

    public List<KeyFlag> getKeyFlagsOf(String userId) {
        if (!isUserIdValid(userId)) {
            return Collections.emptyList();
        }

        PGPSignature userIdCertification = getCurrentUserIdCertification(userId);
        if (userIdCertification == null) {
            return Collections.emptyList();
        }

        KeyFlags keyFlags = SignatureSubpacketsUtil.getKeyFlags(userIdCertification);
        if (keyFlags != null) {
            return KeyFlag.fromBitmask(keyFlags.getFlags());
        }
        return Collections.emptyList();
    }

    /**
     * Return the algorithm of the primary key.
     *
     * @return public key algorithm
     */
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.fromId(getPublicKey().getAlgorithm());
    }

    /**
     * Return the creation date of the primary key.
     *
     * @return creation date
     */
    public Date getCreationDate() {
        return getPublicKey().getCreationTime();
    }

    /**
     * Return the date on which the key ring was last modified.
     * This date corresponds to the date of the last signature that was made on this key ring by the primary key.
     *
     * @return last modification date.
     */
    public Date getLastModified() {
        PGPSignature mostRecent = getMostRecentSignature();
        return mostRecent.getCreationTime();
    }

    private PGPSignature getMostRecentSignature() {
        Set<PGPSignature> allSignatures = new HashSet<>();
        PGPSignature mostRecentSelfSignature = getCurrentDirectKeySelfSignature();
        PGPSignature revocationSelfSignature = getRevocationSelfSignature();
        if (mostRecentSelfSignature != null) allSignatures.add(mostRecentSelfSignature);
        if (revocationSelfSignature != null) allSignatures.add(revocationSelfSignature);
        allSignatures.addAll(signatures.userIdCertifications.values());
        allSignatures.addAll(signatures.userIdRevocations.values());
        allSignatures.addAll(signatures.subkeyBindings.values());
        allSignatures.addAll(signatures.subkeyRevocations.values());

        PGPSignature mostRecent = null;
        for (PGPSignature signature : allSignatures) {
            if (mostRecent == null || signature.getCreationTime().after(mostRecent.getCreationTime())) {
                mostRecent = signature;
            }
        }
        return mostRecent;
    }

    /**
     * Return the date on which the primary key was revoked, or null if it has not yet been revoked.
     *
     * @return revocation date or null
     */
    public Date getRevocationDate() {
        return getRevocationSelfSignature() == null ? null : getRevocationSelfSignature().getCreationTime();
    }

    /**
     * Return the date of expiration of the primary key or null if the key has no expiration date.
     *
     * @return expiration date
     */
    public Date getPrimaryKeyExpirationDate() {
        Date lastExpiration = null;
        if (getCurrentDirectKeySelfSignature() != null) {
            lastExpiration = SignatureUtils.getKeyExpirationDate(getCreationDate(), getCurrentDirectKeySelfSignature());
        }

        for (String userId : getValidUserIds()) {
            PGPSignature signature = getCurrentUserIdCertification(userId);
            Date expiration = SignatureUtils.getKeyExpirationDate(getCreationDate(), signature);
            if (expiration != null && (lastExpiration == null || expiration.after(lastExpiration))) {
                lastExpiration = expiration;
            }
        }
        return lastExpiration;
    }

    public Date getSubkeyExpirationDate(OpenPgpV4Fingerprint fingerprint) {
        if (getPublicKey().getKeyID() == fingerprint.getKeyId()) {
            return getPrimaryKeyExpirationDate();
        }

        PGPPublicKey subkey = getPublicKey(fingerprint.getKeyId());
        if (subkey == null) {
            throw new IllegalArgumentException("No subkey with fingerprint " + fingerprint + " found.");
        }
        return SignatureUtils.getKeyExpirationDate(subkey.getCreationTime(), getCurrentSubkeyBindingSignature(fingerprint.getKeyId()));
    }

    /**
     * Return true if the key ring is a {@link PGPSecretKeyRing}.
     * If it is a {@link PGPPublicKeyRing} return false and if it is neither, throw an {@link AssertionError}.
     *
     * @return true if the key ring is a secret key ring.
     */
    public boolean isSecretKey() {
        if (keys instanceof PGPSecretKeyRing) {
            return true;
        } else if (keys instanceof PGPPublicKeyRing) {
            return false;
        } else {
            throw new AssertionError("Expected PGPKeyRing to be either PGPPublicKeyRing or PGPSecretKeyRing, but got " + keys.getClass().getName() + " instead.");
        }
    }

    /**
     * Returns true when every secret key on the key ring is not encrypted.
     * If there is at least one encrypted secret key on the key ring, returns false.
     * If the key ring is a {@link PGPPublicKeyRing}, returns true.
     * Sub-keys with S2K of a type GNU_DUMMY_S2K do not affect the result.
     *
     * @return true if all secret keys are unencrypted.
     */
    public boolean isFullyDecrypted() {
        if (isSecretKey()) {
            for (PGPSecretKey secretKey : getSecretKeys()) {
                if (!KeyInfo.hasDummyS2K(secretKey) && KeyInfo.isEncrypted(secretKey)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Returns true when every secret key on the key ring is encrypted.
     * If there is at least one not encrypted secret key on the key ring, returns false.
     * If the key ring is a {@link PGPPublicKeyRing}, returns false.
     * Sub-keys with S2K of a type GNU_DUMMY_S2K do not affect a result.
     *
     * @return true if all secret keys are encrypted.
     */
    public boolean isFullyEncrypted() {
        if (isSecretKey()) {
            for (PGPSecretKey secretKey : getSecretKeys()) {
                if (!KeyInfo.hasDummyS2K(secretKey) && KeyInfo.isDecrypted(secretKey)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public PGPPublicKey getEncryptionSubkey(EncryptionStream.Purpose purpose) {
        Iterator<PGPPublicKey> subkeys = keys.getPublicKeys();
        while (subkeys.hasNext()) {
            PGPPublicKey subKey = subkeys.next();

            if (!isKeyValidlyBound(subKey.getKeyID())) {
                continue;
            }

            if (!subKey.isEncryptionKey()) {
                continue;
            }

            List<KeyFlag> keyFlags = getKeyFlagsOf(subKey.getKeyID());
            switch (purpose) {
                case COMMUNICATIONS:
                    if (keyFlags.contains(KeyFlag.ENCRYPT_COMMS)) {
                        return subKey;
                    }
                    break;
                case STORAGE:
                    if (keyFlags.contains(KeyFlag.ENCRYPT_STORAGE)) {
                        return subKey;
                    }
                    break;
                case STORAGE_AND_COMMUNICATIONS:
                    if (keyFlags.contains(KeyFlag.ENCRYPT_COMMS) || keyFlags.contains(KeyFlag.ENCRYPT_STORAGE)) {
                        return subKey;
                    }
                    break;
            }
        }
        return null;
    }

    public PGPPublicKey getEncryptionSubkey(String userId, EncryptionStream.Purpose purpose) {
        if (userId != null) {
            if (!isUserIdValid(userId)) {
                throw new KeyValidationException(userId, getCurrentUserIdCertification(userId), getUserIdRevocation(userId));
            }
        }

        return getEncryptionSubkey(purpose);
    }

    public PGPPublicKey getSigningSubkey() {
        Iterator<PGPPublicKey> subkeys = keys.getPublicKeys();
        while (subkeys.hasNext()) {
            PGPPublicKey subKey = subkeys.next();

            if (!isKeyValidlyBound(subKey.getKeyID())) {
                continue;
            }

            if (!subKey.isEncryptionKey()) {
                continue;
            }

            List<KeyFlag> keyFlags = getKeyFlagsOf(subKey.getKeyID());
            if (keyFlags.contains(KeyFlag.SIGN_DATA)) {
                return subKey;
            }
        }
        return null;
    }

    public List<HashAlgorithm> getPreferredHashAlgorithms(String userId, long keyID) {
        PGPSignature signature = getCurrentUserIdCertification(userId == null ? getPrimaryUserId() : userId);
        if (signature == null) {
            signature = getCurrentDirectKeySelfSignature();
        }
        if (signature == null) {
            signature = getCurrentSubkeyBindingSignature(keyID);
        }
        if (signature == null) {
            throw new IllegalStateException("No valid signature.");
        }
        return SignatureSubpacketsUtil.parsePreferredHashAlgorithms(signature);
    }

    public static class Signatures {

        private final PGPSignature primaryKeyRevocation;
        private final PGPSignature primaryKeySelfSignature;
        private final Map<String, PGPSignature> userIdRevocations;
        private final Map<String, PGPSignature> userIdCertifications;
        private final Map<Long, PGPSignature> subkeyRevocations;
        private final Map<Long, PGPSignature> subkeyBindings;

        public Signatures(PGPKeyRing keyRing, Date evaluationDate, Policy policy) {
            primaryKeyRevocation = SignaturePicker.pickCurrentRevocationSelfSignature(keyRing, evaluationDate);
            primaryKeySelfSignature = SignaturePicker.pickCurrentDirectKeySelfSignature(keyRing, evaluationDate);
            userIdRevocations = new HashMap<>();
            userIdCertifications = new HashMap<>();
            subkeyRevocations = new HashMap<>();
            subkeyBindings = new HashMap<>();

            for (Iterator<String> it = keyRing.getPublicKey().getUserIDs(); it.hasNext(); ) {
                String userId = it.next();
                PGPSignature revocation = SignaturePicker.pickCurrentUserIdRevocationSignature(keyRing, userId, evaluationDate);
                if (revocation != null) {
                    userIdRevocations.put(userId, revocation);
                }
                PGPSignature certification = SignaturePicker.pickCurrentUserIdCertificationSignature(keyRing, userId, evaluationDate);
                if (certification != null) {
                    userIdCertifications.put(userId, certification);
                }
            }

            Iterator<PGPPublicKey> keys = keyRing.getPublicKeys();
            keys.next(); // Skip primary key
            while (keys.hasNext()) {
                PGPPublicKey subkey = keys.next();
                PGPSignature subkeyRevocation = SignaturePicker.pickCurrentSubkeyBindingRevocationSignature(keyRing, subkey, evaluationDate);
                if (subkeyRevocation != null) {
                    subkeyRevocations.put(subkey.getKeyID(), subkeyRevocation);
                }
                PGPSignature subkeyBinding = SignaturePicker.pickCurrentSubkeyBindingSignature(keyRing, subkey, evaluationDate);
                if (subkeyBinding != null) {
                    subkeyBindings.put(subkey.getKeyID(), subkeyBinding);
                }
            }
        }

    }
}
