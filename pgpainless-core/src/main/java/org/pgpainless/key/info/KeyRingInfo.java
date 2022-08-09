// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

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
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.SignaturePicker;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

/**
 * Utility class to quickly extract certain information from a {@link PGPPublicKeyRing}/{@link PGPSecretKeyRing}.
 */
public class KeyRingInfo {

    private static final Pattern PATTERN_EMAIL_FROM_USERID = Pattern.compile("<([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)>");
    private static final Pattern PATTERN_EMAIL_EXPLICIT = Pattern.compile("^([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)$");

    private final PGPKeyRing keys;
    private final Signatures signatures;
    private final Date referenceDate;
    private final String primaryUserId;

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
        this(keys, PGPainless.getPolicy(), validationDate);
    }

    /**
     * Evaluate the key ring at the provided validation date.
     *
     * @param keys key ring
     * @param policy policy
     * @param validationDate validation date
     */
    public KeyRingInfo(PGPKeyRing keys, Policy policy, Date validationDate) {
        this.keys = keys;
        this.signatures = new Signatures(keys, validationDate, policy);
        this.referenceDate = validationDate;
        this.primaryUserId = findPrimaryUserId();
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
    public @Nullable PGPPublicKey getPublicKey(OpenPgpFingerprint fingerprint) {
        return getPublicKey(fingerprint.getKeyId());
    }

    /**
     * Return the public key with the given key id.
     *
     * @param keyId key id
     * @return public key or null
     */
    public @Nullable PGPPublicKey getPublicKey(long keyId) {
        return getPublicKey(keys, keyId);
    }

    /**
     * Return the public key with the given key id from the provided key ring.
     *
     * @param keyRing key ring
     * @param keyId key id
     * @return public key or null
     */
    public static @Nullable PGPPublicKey getPublicKey(PGPKeyRing keyRing, long keyId) {
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
            if (signatures.primaryKeyRevocation != null && SignatureUtils.isHardRevocation(signatures.primaryKeyRevocation)) {
                return false;
            }
            return signatures.primaryKeyRevocation == null;
        }

        PGPSignature binding = signatures.subkeyBindings.get(keyId);
        PGPSignature revocation = signatures.subkeyRevocations.get(keyId);

        // No valid binding
        if (binding == null || SignatureUtils.isSignatureExpired(binding)) {
            return false;
        }

        // Revocation
        if (revocation != null) {
            if (SignatureUtils.isHardRevocation(revocation)) {
                // Subkey is hard revoked
                return false;
            } else {
                // Key is soft-revoked, not yet re-bound
                return SignatureUtils.isSignatureExpired(revocation)
                        || !revocation.getCreationTime().after(binding.getCreationTime());
            }
        }

        return true;
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
    public @Nullable PGPSecretKey getSecretKey() {
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
    public @Nullable PGPSecretKey getSecretKey(OpenPgpFingerprint fingerprint) {
        return getSecretKey(fingerprint.getKeyId());
    }

    /**
     * Return the secret key with the given key id.
     *
     * @param keyId key id
     * @return secret key or null
     */
    public @Nullable PGPSecretKey getSecretKey(long keyId) {
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
     * Return the {@link OpenPgpFingerprint} of this key ring.
     *
     * @return fingerprint
     */
    public OpenPgpFingerprint getFingerprint() {
        return OpenPgpFingerprint.of(getPublicKey());
    }

    public @Nullable String getPrimaryUserId() {
        return primaryUserId;
    }

    /**
     * Return the current primary user-id of the key ring.
     *
     * Note: If no user-id is marked as primary key using a {@link PrimaryUserID} packet,
     * this method returns the first user-id on the key, otherwise null.
     *
     * @return primary user-id or null
     */
    private String findPrimaryUserId() {
        String primaryUserId = null;
        Date currentModificationDate = null;

        List<String> userIds = getUserIds();
        if (userIds.isEmpty()) {
            return null;
        }

        String firstUserId = null;
        for (String userId : userIds) {
            PGPSignature certification = signatures.userIdCertifications.get(userId);
            if (certification == null) {
                continue;
            }

            if (firstUserId == null) {
                firstUserId = userId;
            }
            Date creationTime = certification.getCreationTime();

            if (certification.getHashedSubPackets().isPrimaryUserID()) {
                if (currentModificationDate == null || creationTime.after(currentModificationDate)) {
                    primaryUserId = userId;
                    currentModificationDate = creationTime;
                }

            }
        }

        if (primaryUserId != null) {
            return primaryUserId;
        }

        return firstUserId;
    }

    /**
     * Return a list of all user-ids of the primary key.
     * Note: This list might also contain expired / revoked user-ids.
     * Consider using {@link #getValidUserIds()} instead.
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
            if (isUserIdBound(userId)) {
                valid.add(userId);
            }
        }
        return valid;
    }

    /**
     * Return a list of all user-ids that were valid at some point, but might be expired by now.
     *
     * @return bound user-ids
     */
    public List<String> getValidAndExpiredUserIds() {
        List<String> probablyExpired = new ArrayList<>();
        List<String> userIds = getUserIds();

        for (String userId : userIds) {
            PGPSignature certification = signatures.userIdCertifications.get(userId);
            PGPSignature revocation = signatures.userIdRevocations.get(userId);

            // Unbound user-id
            if (certification == null) {
                continue;
            }

            // Not revoked -> valid
            if (revocation == null) {
                probablyExpired.add(userId);
                continue;
            }

            // Hard revocation -> invalid
            if (SignatureUtils.isHardRevocation(revocation)) {
                continue;
            }

            // Soft revocation -> valid if certification is newer than revocation (revalidation)
            if (certification.getCreationTime().after(revocation.getCreationTime())) {
                probablyExpired.add(userId);
            }
        }
        return probablyExpired;
    }

    /**
     * Return true if the provided user-id is valid.
     *
     * @param userId user-id
     * @return true if user-id is valid
     */
    public boolean isUserIdValid(String userId) {
        if (!userId.equals(primaryUserId)) {
            if (!isUserIdBound(primaryUserId)) {
                // primary user-id not valid
                return false;
            }
        }
        return isUserIdBound(userId);
    }


    private boolean isUserIdBound(String userId) {

        PGPSignature certification = signatures.userIdCertifications.get(userId);
        PGPSignature revocation = signatures.userIdRevocations.get(userId);

        if (certification == null) {
            return false;
        }
        if (SignatureUtils.isSignatureExpired(certification)) {
            return false;
        }
        if (certification.getHashedSubPackets().isPrimaryUserID()) {
            Date keyExpiration = SignatureSubpacketsUtil.getKeyExpirationTimeAsDate(certification, keys.getPublicKey());
            if (keyExpiration != null && referenceDate.after(keyExpiration)) {
                return false;
            }
        }
        // Not revoked -> valid
        if (revocation == null) {
            return true;
        }
        // Hard revocation -> invalid
        if (SignatureUtils.isHardRevocation(revocation)) {
            return false;
        }
        // Soft revocation -> valid if certification is newer than revocation (revalidation)
        return certification.getCreationTime().after(revocation.getCreationTime());
    }

    /**
     * Return a list of all user-ids of the primary key that appear to be email-addresses.
     * Note: This list might contain expired / revoked user-ids.
     *
     * @return email addresses
     */
    public List<String> getEmailAddresses() {
        List<String> userIds = getUserIds();
        List<String> emails = new ArrayList<>();
        for (String userId : userIds) {
            Matcher matcher = PATTERN_EMAIL_FROM_USERID.matcher(userId);
            if (matcher.find()) {
                emails.add(matcher.group(1));
            } else {
                matcher = PATTERN_EMAIL_EXPLICIT.matcher(userId);
                if (matcher.find()) {
                    emails.add(matcher.group(1));
                }
            }
        }
        return emails;
    }

    /**
     * Return the latest direct-key self signature.
     *
     * Note: This signature might be expired (check with {@link SignatureUtils#isSignatureExpired(PGPSignature)}).
     *
     * @return latest direct key self-signature or null
     */
    public @Nullable PGPSignature getLatestDirectKeySelfSignature() {
        return signatures.primaryKeySelfSignature;
    }

    /**
     * Return the latest revocation self-signature on the primary key.
     *
     * @return revocation or null
     */
    public @Nullable PGPSignature getRevocationSelfSignature() {
        return signatures.primaryKeyRevocation;
    }

    /**
     * Return the latest certification self-signature on the provided user-id.
     *
     * @param userId user-id
     * @return certification signature or null
     */
    public @Nullable PGPSignature getLatestUserIdCertification(String userId) {
        return signatures.userIdCertifications.get(userId);
    }

    /**
     * Return the latest user-id revocation signature for the provided user-id.
     *
     * @param userId user-id
     * @return revocation or null
     */
    public @Nullable PGPSignature getUserIdRevocation(String userId) {
        return signatures.userIdRevocations.get(userId);
    }

    /**
     * Return the currently active subkey binding signature for the subkey with the provided key-id.
     *
     * @param keyId subkey id
     * @return subkey binding signature or null
     */
    public @Nullable PGPSignature getCurrentSubkeyBindingSignature(long keyId) {
        return signatures.subkeyBindings.get(keyId);
    }

    /**
     * Return the latest subkey binding revocation signature for the subkey with the given key-id.
     *
     * @param keyId subkey id
     * @return subkey binding revocation or null
     */
    public @Nullable PGPSignature getSubkeyRevocationSignature(long keyId) {
        return signatures.subkeyRevocations.get(keyId);
    }

    /**
     * Return a list of {@link KeyFlag KeyFlags} that apply to the subkey with the provided key id.
     * @param keyId key-id
     * @return list of key flags
     */
    public @Nonnull List<KeyFlag> getKeyFlagsOf(long keyId) {
        // key is primary key
        if (getPublicKey().getKeyID() == keyId) {

            PGPSignature directKeySignature = getLatestDirectKeySelfSignature();
            if (directKeySignature != null) {
                List<KeyFlag> keyFlags = SignatureSubpacketsUtil.parseKeyFlags(directKeySignature);
                if (keyFlags != null) {
                    return keyFlags;
                }
            }

            String primaryUserId = getPrimaryUserId();
            if (primaryUserId != null) {
                PGPSignature userIdSignature = getLatestUserIdCertification(primaryUserId);
                List<KeyFlag> keyFlags = SignatureSubpacketsUtil.parseKeyFlags(userIdSignature);
                if (keyFlags != null) {
                    return keyFlags;
                }
            }
        }
        // Key is subkey
        else {
            PGPSignature bindingSignature = getCurrentSubkeyBindingSignature(keyId);
            if (bindingSignature != null) {
                List<KeyFlag> keyFlags = SignatureSubpacketsUtil.parseKeyFlags(bindingSignature);
                if (keyFlags != null) {
                    return keyFlags;
                }
            }
        }
        return Collections.emptyList();
    }

    /**
     * Return a list of {@link KeyFlag KeyFlags} that apply to the given user-id.
     *
     * @param userId user-id
     * @return key flags
     */
    public @Nonnull List<KeyFlag> getKeyFlagsOf(String userId) {
        if (!isUserIdValid(userId)) {
            return Collections.emptyList();
        }

        PGPSignature userIdCertification = getLatestUserIdCertification(userId);
        if (userIdCertification == null) {
            throw new AssertionError("While user-id '" + userId + "' was reported as valid, there appears to be no certification for it.");
        }

        List<KeyFlag> keyFlags = SignatureSubpacketsUtil.parseKeyFlags(userIdCertification);
        if (keyFlags != null) {
            return keyFlags;
        }
        return Collections.emptyList();
    }

    /**
     * Return the algorithm of the primary key.
     *
     * @return public key algorithm
     */
    @Nonnull
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.requireFromId(getPublicKey().getAlgorithm());
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
    public @Nullable Date getLastModified() {
        PGPSignature mostRecent = getMostRecentSignature();
        if (mostRecent == null) {
            // No sigs found. Return public key creation date instead.
            return getLatestKeyCreationDate();
        }
        return mostRecent.getCreationTime();
    }

    /**
     * Return the creation time of the latest added subkey.
     *
     * @return latest key creation time
     */
    public @Nonnull Date getLatestKeyCreationDate() {
        Date latestCreation = null;
        for (PGPPublicKey key : getPublicKeys()) {
            if (!isKeyValidlyBound(key.getKeyID())) {
                continue;
            }
            Date keyCreation = key.getCreationTime();
            if (latestCreation == null || latestCreation.before(keyCreation)) {
                latestCreation = keyCreation;
            }
        }
        if (latestCreation == null) {
            throw new AssertionError("Apparently there is no validly bound key in this key ring.");
        }
        return latestCreation;
    }

    private @Nullable PGPSignature getMostRecentSignature() {
        Set<PGPSignature> allSignatures = new HashSet<>();
        PGPSignature mostRecentSelfSignature = getLatestDirectKeySelfSignature();
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
    public @Nullable Date getRevocationDate() {
        return getRevocationSelfSignature() == null ? null : getRevocationSelfSignature().getCreationTime();
    }

    /**
     * Return the date of expiration of the primary key or null if the key has no expiration date.
     *
     * @return expiration date
     */
    public @Nullable Date getPrimaryKeyExpirationDate() {
        PGPSignature directKeySig = getLatestDirectKeySelfSignature();
        Date directKeyExpirationDate = null;
        if (directKeySig != null) {
            directKeyExpirationDate = SignatureSubpacketsUtil.getKeyExpirationTimeAsDate(directKeySig, getPublicKey());
        }

        PGPSignature primaryUserIdCertification = null;
        Date userIdExpirationDate = null;
        String possiblyExpiredPrimaryUserId = getPossiblyExpiredPrimaryUserId();
        if (possiblyExpiredPrimaryUserId != null) {
            primaryUserIdCertification = getLatestUserIdCertification(possiblyExpiredPrimaryUserId);
            if (primaryUserIdCertification != null) {
                userIdExpirationDate = SignatureSubpacketsUtil.getKeyExpirationTimeAsDate(primaryUserIdCertification, getPublicKey());
            }
        }

        if (directKeySig == null && primaryUserIdCertification == null) {
            throw new NoSuchElementException("No direct-key signature and no user-id signature found.");
        }

        if (directKeyExpirationDate != null && userIdExpirationDate == null) {
            return directKeyExpirationDate;
        }

        if (directKeyExpirationDate == null) {
            return userIdExpirationDate;
        }

        if (directKeyExpirationDate.before(userIdExpirationDate)) {
            return directKeyExpirationDate;
        }

        return userIdExpirationDate;
    }

    public String getPossiblyExpiredPrimaryUserId() {
        String validPrimaryUserId = getPrimaryUserId();
        if (validPrimaryUserId != null) {
            return validPrimaryUserId;
        }

        Date latestCreationTime = null;
        String primaryUserId = null;
        boolean foundPrimary = false;
        for (String userId : getUserIds()) {
            PGPSignature signature = getLatestUserIdCertification(userId);
            if (signature == null) {
                continue;
            }

            boolean isPrimary = signature.getHashedSubPackets().isPrimaryUserID();
            if (foundPrimary && !isPrimary) {
                continue;
            }

            Date creationTime = signature.getCreationTime();
            if (latestCreationTime == null || creationTime.after(latestCreationTime) || isPrimary && !foundPrimary) {
                latestCreationTime = creationTime;
                primaryUserId = userId;
            }

            foundPrimary |= isPrimary;
        }

        return primaryUserId;
    }

    /**
     * Return the expiration date of the subkey with the provided fingerprint.
     *
     * @param fingerprint subkey fingerprint
     * @return expiration date or null
     */
    public @Nullable Date getSubkeyExpirationDate(OpenPgpFingerprint fingerprint) {
        if (getPublicKey().getKeyID() == fingerprint.getKeyId()) {
            return getPrimaryKeyExpirationDate();
        }

        PGPPublicKey subkey = getPublicKey(fingerprint.getKeyId());
        if (subkey == null) {
            throw new NoSuchElementException("No subkey with fingerprint " + fingerprint + " found.");
        }

        PGPSignature bindingSig = getCurrentSubkeyBindingSignature(fingerprint.getKeyId());
        if (bindingSig == null) {
            throw new AssertionError("Subkey has no valid binding signature.");
        }

        return SignatureUtils.getKeyExpirationDate(subkey.getCreationTime(), bindingSig);
    }

    /**
     * Return the latest date on which  the key ring is still usable for the given key flag.
     * If only a subkey is carrying the required flag and the primary key expires earlier than the subkey,
     * the expiry date of the primary key is returned.
     *
     * This method might return null, if the primary key and a subkey with the required flag does not expire.
     * @param use key flag representing the use case, e.g. {@link KeyFlag#SIGN_DATA} or
     * {@link KeyFlag#ENCRYPT_COMMS}/{@link KeyFlag#ENCRYPT_STORAGE}.
     * @return latest date on which the key ring can be used for the given use case, or null if it can be used indefinitely.
     */
    public Date getExpirationDateForUse(KeyFlag use) {
        if (use == KeyFlag.SPLIT || use == KeyFlag.SHARED) {
            throw new IllegalArgumentException("SPLIT and SHARED are not uses, but properties.");
        }

        Date primaryExpiration = getPrimaryKeyExpirationDate();
        List<PGPPublicKey> nonExpiringSubkeys = new ArrayList<>();
        Date latestSubkeyExpirationDate = null;

        List<PGPPublicKey> keysWithFlag = getKeysWithKeyFlag(use);
        if (keysWithFlag.isEmpty()) {
            throw new NoSuchElementException("No key with the required key flag found.");
        }

        for (PGPPublicKey key : keysWithFlag) {
            Date subkeyExpirationDate = getSubkeyExpirationDate(OpenPgpFingerprint.of(key));
            if (subkeyExpirationDate == null) {
                nonExpiringSubkeys.add(key);
            } else {
                if (latestSubkeyExpirationDate == null || subkeyExpirationDate.after(latestSubkeyExpirationDate)) {
                    latestSubkeyExpirationDate = subkeyExpirationDate;
                }
            }
        }

        if (nonExpiringSubkeys.isEmpty()) {
            if (latestSubkeyExpirationDate != null) {
                if (primaryExpiration == null) {
                    return latestSubkeyExpirationDate;
                }
                if (latestSubkeyExpirationDate.before(primaryExpiration)) {
                    return latestSubkeyExpirationDate;
                }
            }
        }
        return primaryExpiration;
    }

    public boolean isHardRevoked(String userId) {
        PGPSignature revocation = signatures.userIdRevocations.get(userId);
        if (revocation == null) {
            return false;
        }
        RevocationReason revocationReason = revocation.getHashedSubPackets().getRevocationReason();
        return revocationReason == null || RevocationAttributes.Reason.isHardRevocation(revocationReason.getRevocationReason());
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
        if (!isSecretKey()) {
            return true;
        }
        for (PGPSecretKey secretKey : getSecretKeys()) {
            if (!KeyInfo.hasDummyS2K(secretKey) && KeyInfo.isEncrypted(secretKey)) {
                return false;
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
        if (!isSecretKey()) {
            return false;
        }
        for (PGPSecretKey secretKey : getSecretKeys()) {
            if (!KeyInfo.hasDummyS2K(secretKey) && KeyInfo.isDecrypted(secretKey)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return the version number of the public keys format.
     *
     * @return version
     */
    public int getVersion() {
        return keys.getPublicKey().getVersion();
    }

    /**
     * Return a list of all subkeys which can be used for encryption of the given purpose.
     * This list does not include expired or revoked keys.
     *
     * @param purpose purpose (encrypt data at rest / communications)
     * @return encryption subkeys
     */
    public @Nonnull List<PGPPublicKey> getEncryptionSubkeys(EncryptionPurpose purpose) {
        Date primaryExpiration = getPrimaryKeyExpirationDate();
        if (primaryExpiration != null && primaryExpiration.before(new Date())) {
            return Collections.emptyList();
        }

        Iterator<PGPPublicKey> subkeys = keys.getPublicKeys();
        List<PGPPublicKey> encryptionKeys = new ArrayList<>();
        while (subkeys.hasNext()) {
            PGPPublicKey subKey = subkeys.next();

            if (!isKeyValidlyBound(subKey.getKeyID())) {
                continue;
            }

            Date subkeyExpiration = getSubkeyExpirationDate(OpenPgpFingerprint.of(subKey));
            if (subkeyExpiration != null && subkeyExpiration.before(new Date())) {
                continue;
            }

            if (!subKey.isEncryptionKey()) {
                continue;
            }

            List<KeyFlag> keyFlags = getKeyFlagsOf(subKey.getKeyID());
            switch (purpose) {
                case COMMUNICATIONS:
                    if (keyFlags.contains(KeyFlag.ENCRYPT_COMMS)) {
                        encryptionKeys.add(subKey);
                    }
                    break;
                case STORAGE:
                    if (keyFlags.contains(KeyFlag.ENCRYPT_STORAGE)) {
                        encryptionKeys.add(subKey);
                    }
                    break;
                case ANY:
                    if (keyFlags.contains(KeyFlag.ENCRYPT_COMMS) || keyFlags.contains(KeyFlag.ENCRYPT_STORAGE)) {
                        encryptionKeys.add(subKey);
                    }
                    break;
            }
        }
        return encryptionKeys;
    }

    /**
     * Return a list of all keys which carry the provided key flag in their signature.
     *
     * @param flag flag
     * @return keys with flag
     */
    public List<PGPPublicKey> getKeysWithKeyFlag(KeyFlag flag) {
        List<PGPPublicKey> keysWithFlag = new ArrayList<>();
        for (PGPPublicKey key : getPublicKeys()) {
            List<KeyFlag> keyFlags = getKeyFlagsOf(key.getKeyID());
            if (keyFlags.contains(flag)) {
                keysWithFlag.add(key);
            }
        }

        return keysWithFlag;
    }

    /**
     * Return a list of all subkeys that can be used for encryption with the given user-id.
     * This list does not include expired or revoked keys.
     * TODO: Does it make sense to pass in a user-id?
     *   Aren't the encryption subkeys the same, regardless of which user-id is used?
     *
     * @param userId user-id
     * @param purpose encryption purpose
     * @return encryption subkeys
     */
    public @Nonnull List<PGPPublicKey> getEncryptionSubkeys(String userId, EncryptionPurpose purpose) {
        if (userId != null && !isUserIdValid(userId)) {
            throw new KeyException.UnboundUserIdException(
                    OpenPgpFingerprint.of(keys),
                    userId,
                    getLatestUserIdCertification(userId),
                    getUserIdRevocation(userId)
            );
        }

        return getEncryptionSubkeys(purpose);
    }

    /**
     * Return a list of all subkeys which can be used to sign data.
     *
     * @return signing keys
     */
    public @Nonnull List<PGPPublicKey> getSigningSubkeys() {
        Iterator<PGPPublicKey> subkeys = keys.getPublicKeys();
        List<PGPPublicKey> signingKeys = new ArrayList<>();
        while (subkeys.hasNext()) {
            PGPPublicKey subKey = subkeys.next();

            if (!isKeyValidlyBound(subKey.getKeyID())) {
                continue;
            }

            List<KeyFlag> keyFlags = getKeyFlagsOf(subKey.getKeyID());
            if (keyFlags.contains(KeyFlag.SIGN_DATA)) {
                signingKeys.add(subKey);
            }
        }
        return signingKeys;
    }

    public Set<HashAlgorithm> getPreferredHashAlgorithms() {
        return getPreferredHashAlgorithms(getPrimaryUserId());
    }

    public Set<HashAlgorithm> getPreferredHashAlgorithms(String userId) {
        return getKeyAccessor(userId, getKeyId()).getPreferredHashAlgorithms();
    }

    public Set<HashAlgorithm> getPreferredHashAlgorithms(long keyId) {
        return new KeyAccessor.SubKey(this, new SubkeyIdentifier(keys, keyId))
                .getPreferredHashAlgorithms();
    }

    public Set<SymmetricKeyAlgorithm> getPreferredSymmetricKeyAlgorithms() {
        return getPreferredSymmetricKeyAlgorithms(getPrimaryUserId());
    }

    public Set<SymmetricKeyAlgorithm> getPreferredSymmetricKeyAlgorithms(String userId) {
        return getKeyAccessor(userId, getKeyId()).getPreferredSymmetricKeyAlgorithms();
    }

    public Set<SymmetricKeyAlgorithm> getPreferredSymmetricKeyAlgorithms(long keyId) {
        return new KeyAccessor.SubKey(this, new SubkeyIdentifier(keys, keyId)).getPreferredSymmetricKeyAlgorithms();
    }

    public Set<CompressionAlgorithm> getPreferredCompressionAlgorithms() {
        return getPreferredCompressionAlgorithms(getPrimaryUserId());
    }

    public Set<CompressionAlgorithm> getPreferredCompressionAlgorithms(String userId) {
        return getKeyAccessor(userId, getKeyId()).getPreferredCompressionAlgorithms();
    }

    public Set<CompressionAlgorithm> getPreferredCompressionAlgorithms(long keyId) {
        return new KeyAccessor.SubKey(this, new SubkeyIdentifier(keys, keyId)).getPreferredCompressionAlgorithms();
    }

    /**
     * Returns true, if the certificate has at least one usable encryption subkey.
     *
     * @return true if usable for encryption
     */
    public boolean isUsableForEncryption() {
        return isUsableForEncryption(EncryptionPurpose.ANY);
    }

    /**
     * Returns true, if the certificate has at least one usable encryption subkey for the given purpose.
     *
     * @param purpose purpose of encryption
     * @return true if usable for encryption
     */
    public boolean isUsableForEncryption(@Nonnull EncryptionPurpose purpose) {
        return isKeyValidlyBound(getKeyId()) && !getEncryptionSubkeys(purpose).isEmpty();
    }

    /**
     * Returns true, if the key ring is capable of signing.
     * Contrary to {@link #isUsableForSigning()}, this method also returns true, if this {@link KeyRingInfo} is based
     * on a key ring which has at least one valid public key marked for signing.
     * The secret key is not required for the key ring to qualify as signing capable.
     *
     * @return true if key corresponding to the cert is capable of signing
     */
    public boolean isSigningCapable() {
        // check if primary-key is revoked / expired
        if (!isKeyValidlyBound(getKeyId())) {
            return false;
        }
        // check if it has signing-capable key
        return !getSigningSubkeys().isEmpty();
    }

    /**
     * Returns true, if this {@link KeyRingInfo} is based on a {@link PGPSecretKeyRing}, which has a valid signing key
     * which is ready to be used (i.e. secret key is present and is not on a smart-card).
     *
     * If you just want to check, whether a key / certificate has signing capable subkeys,
     * use {@link #isSigningCapable()} instead.
     *
     * @return true if key is ready to be used for signing
     */
    public boolean isUsableForSigning() {
        if (!isSigningCapable()) {
            return false;
        }

        List<PGPPublicKey> signingKeys = getSigningSubkeys();
        for (PGPPublicKey pk : signingKeys) {
            PGPSecretKey sk = getSecretKey(pk.getKeyID());
            if (sk == null) {
                // Missing secret key
                continue;
            }
            S2K s2K = sk.getS2K();
            // Unencrypted key
            if (s2K == null) {
                return true;
            }

            // Secret key on smart-card
            int s2kType = s2K.getType();
            if (s2kType >= 100 && s2kType <= 110) {
                continue;
            }
            // protected secret key
            return true;
        }
        // No usable secret key found
        return false;
    }

    private KeyAccessor getKeyAccessor(@Nullable String userId, long keyID) {
        if (getPublicKey(keyID) == null) {
            throw new NoSuchElementException("No subkey with key id " + Long.toHexString(keyID) + " found on this key.");
        }
        if (userId != null && !getUserIds().contains(userId)) {
            throw new NoSuchElementException("No user-id '" + userId + "' found on this key.");
        }
        return userId == null ? new KeyAccessor.ViaKeyId(this, new SubkeyIdentifier(keys, keyID))
                : new KeyAccessor.ViaUserId(this, new SubkeyIdentifier(keys, keyID), userId);
    }

    public static class Signatures {

        private final PGPSignature primaryKeyRevocation;
        private final PGPSignature primaryKeySelfSignature;
        private final Map<String, PGPSignature> userIdRevocations;
        private final Map<String, PGPSignature> userIdCertifications;
        private final Map<Long, PGPSignature> subkeyRevocations;
        private final Map<Long, PGPSignature> subkeyBindings;

        public Signatures(PGPKeyRing keyRing, Date referenceDate, Policy policy) {
            primaryKeyRevocation = SignaturePicker.pickCurrentRevocationSelfSignature(keyRing, policy, referenceDate);
            primaryKeySelfSignature = SignaturePicker.pickLatestDirectKeySignature(keyRing, policy, referenceDate);
            userIdRevocations = new HashMap<>();
            userIdCertifications = new HashMap<>();
            subkeyRevocations = new HashMap<>();
            subkeyBindings = new HashMap<>();

            for (Iterator<String> it = keyRing.getPublicKey().getUserIDs(); it.hasNext(); ) {
                String userId = it.next();
                PGPSignature revocation = SignaturePicker.pickCurrentUserIdRevocationSignature(keyRing, userId, policy, referenceDate);
                if (revocation != null) {
                    userIdRevocations.put(userId, revocation);
                }
                PGPSignature certification = SignaturePicker.pickLatestUserIdCertificationSignature(keyRing, userId, policy, referenceDate);
                if (certification != null) {
                    userIdCertifications.put(userId, certification);
                }
            }

            Iterator<PGPPublicKey> keys = keyRing.getPublicKeys();
            keys.next(); // Skip primary key
            while (keys.hasNext()) {
                PGPPublicKey subkey = keys.next();
                PGPSignature subkeyRevocation = SignaturePicker.pickCurrentSubkeyBindingRevocationSignature(keyRing, subkey, policy, referenceDate);
                if (subkeyRevocation != null) {
                    subkeyRevocations.put(subkey.getKeyID(), subkeyRevocation);
                }
                PGPSignature subkeyBinding = SignaturePicker.pickLatestSubkeyBindingSignature(keyRing, subkey, policy, referenceDate);
                if (subkeyBinding != null) {
                    subkeyBindings.put(subkey.getKeyID(), subkeyBinding);
                }
            }
        }
    }
}
