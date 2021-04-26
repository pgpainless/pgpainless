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
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.signature.SignaturePicker;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

/**
 * Utility class to quickly extract certain information from a {@link PGPPublicKeyRing}/{@link PGPSecretKeyRing}.
 */
public class KeyRingInfo {

    private static final Pattern PATTERN_EMAIL = Pattern.compile("[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}");

    private final PGPKeyRing keys;

    private final PGPSignature revocationSelfSignature;
    private final PGPSignature mostRecentSelfSignature;
    private final Map<String, PGPSignature> mostRecentUserIdSignatures = new ConcurrentHashMap<>();
    private final Map<String, PGPSignature> mostRecentUserIdRevocations = new ConcurrentHashMap<>();
    private final Map<Long, PGPSignature> mostRecentSubkeyBindings = new ConcurrentHashMap<>();
    private final Map<Long, PGPSignature> mostRecentSubkeyRevocations = new ConcurrentHashMap<>();

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

    public KeyRingInfo(PGPKeyRing keys, Date validationDate) {
        this.keys = keys;

        revocationSelfSignature = SignaturePicker.pickCurrentRevocationSelfSignature(keys, validationDate);
        mostRecentSelfSignature = SignaturePicker.pickCurrentDirectKeySelfSignature(keys, validationDate);

        for (Iterator<String> it = keys.getPublicKey().getUserIDs(); it.hasNext(); ) {
            String userId = it.next();
            PGPSignature certification = SignaturePicker.pickCurrentUserIdCertificationSignature(keys, userId, validationDate);
            if (certification != null) {
                mostRecentUserIdSignatures.put(userId, certification);
            }
            PGPSignature revocation = SignaturePicker.pickCurrentUserIdRevocationSignature(keys, userId, validationDate);
            if (revocation != null) {
                mostRecentUserIdRevocations.put(userId, revocation);
            }
        }

        Iterator<PGPPublicKey> publicKeys = keys.getPublicKeys();
        publicKeys.next(); // Skip primary key

        while (publicKeys.hasNext()) {
            PGPPublicKey subkey = publicKeys.next();
            PGPSignature bindingSig = SignaturePicker.pickCurrentSubkeyBindingSignature(keys, subkey, validationDate);
            if (bindingSig != null) {
                mostRecentSubkeyBindings.put(subkey.getKeyID(), bindingSig);
            }
            PGPSignature bindingRevocation = SignaturePicker.pickCurrentSubkeyBindingRevocationSignature(keys, subkey, validationDate);
            if (bindingRevocation != null) {
                mostRecentSubkeyRevocations.put(subkey.getKeyID(), bindingRevocation);
            }
        }
    }

    /**
     * Return the first {@link PGPPublicKey} of this key ring.
     *
     * @return public key
     */
    public PGPPublicKey getPublicKey() {
        return keys.getPublicKey();
    }

    public PGPPublicKey getPublicKey(OpenPgpV4Fingerprint fingerprint) {
        return getPublicKey(fingerprint.getKeyId());
    }

    public PGPPublicKey getPublicKey(long keyId) {
        return keys.getPublicKey(keyId);
    }

    public static PGPPublicKey getPublicKey(PGPKeyRing keyRing, long keyId) {
        return keyRing.getPublicKey(keyId);
    }

    public boolean isKeyValidlyBound(long keyId) {
        PGPPublicKey publicKey = keys.getPublicKey(keyId);
        if (publicKey == null) {
            return false;
        }

        if (publicKey == getPublicKey()) {
            return revocationSelfSignature == null;
        } else {
            PGPSignature binding = mostRecentSubkeyBindings.get(keyId);
            PGPSignature revocation = mostRecentSubkeyRevocations.get(keyId);
            return binding != null && revocation == null;
        }
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

    public PGPSecretKey getSecretKey(OpenPgpV4Fingerprint fingerprint) {
        return getSecretKey(fingerprint.getKeyId());
    }

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

    public String getPrimaryUserId() {
        String primaryUserId = null;
        Date modificationDate = null;
        for (String userId : getValidUserIds()) {
            PGPSignature signature = mostRecentUserIdSignatures.get(userId);
            PrimaryUserID subpacket = SignatureSubpacketsUtil.getPrimaryUserId(signature);
            if (subpacket != null && subpacket.isPrimaryUserID()) {
                // if there are multiple primary userIDs, return most recently signed
                if (modificationDate == null || modificationDate.before(signature.getCreationTime())) {
                    primaryUserId = userId;
                    modificationDate = signature.getCreationTime();
                }
            }
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

    public boolean isUserIdValid(String userId) {
        PGPSignature certification = mostRecentUserIdSignatures.get(userId);
        PGPSignature revocation = mostRecentUserIdRevocations.get(userId);

        if (certification == null) {
            return false;
        }
        return revocation == null;
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

    public PGPSignature getCurrentDirectKeySelfSignature() {
        return mostRecentSelfSignature;
    }

    public PGPSignature getRevocationSelfSignature() {
        return revocationSelfSignature;
    }

    public PGPSignature getCurrentUserIdCertification(String userId) {
        return mostRecentUserIdSignatures.get(userId);
    }

    public PGPSignature getUserIdRevocation(String userId) {
        return mostRecentUserIdRevocations.get(userId);
    }

    public PGPSignature getCurrentSubkeyBindingSignature(long keyId) {
        return mostRecentSubkeyBindings.get(keyId);
    }

    public PGPSignature getSubkeyRevocationSignature(long keyId) {
        return mostRecentSubkeyRevocations.get(keyId);
    }

    public List<KeyFlag> getKeyFlagsOf(long keyId) {
        if (getPublicKey().getKeyID() == keyId) {

            if (mostRecentSelfSignature != null) {
                KeyFlags flags = SignatureSubpacketsUtil.getKeyFlags(mostRecentSelfSignature);
                if (flags != null) {
                    return KeyFlag.fromBitmask(flags.getFlags());
                }
            }

            String primaryUserId = getPrimaryUserId();
            if (primaryUserId != null) {
                KeyFlags flags = SignatureSubpacketsUtil.getKeyFlags(mostRecentUserIdSignatures.get(primaryUserId));
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

        PGPSignature userIdCertification = mostRecentUserIdSignatures.get(userId);
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
        if (mostRecentSelfSignature != null) allSignatures.add(mostRecentSelfSignature);
        if (revocationSelfSignature != null) allSignatures.add(revocationSelfSignature);
        allSignatures.addAll(mostRecentUserIdSignatures.values());
        allSignatures.addAll(mostRecentUserIdRevocations.values());
        allSignatures.addAll(mostRecentSubkeyBindings.values());
        allSignatures.addAll(mostRecentSubkeyRevocations.values());

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
        return revocationSelfSignature == null ? null : revocationSelfSignature.getCreationTime();
    }

    /**
     * Return the date of expiration of the primary key or null if the key has no expiration date.
     *
     * @return expiration date
     */
    public Date getPrimaryKeyExpirationDate() {
        Date lastExpiration = null;
        if (mostRecentSelfSignature != null) {
            lastExpiration = SignatureUtils.getKeyExpirationDate(getCreationDate(), mostRecentSelfSignature);
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
        return SignatureUtils.getKeyExpirationDate(subkey.getCreationTime(), mostRecentSubkeyBindings.get(fingerprint.getKeyId()));
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
}
