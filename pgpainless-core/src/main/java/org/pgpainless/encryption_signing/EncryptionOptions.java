// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.authentication.CertificateAuthenticity;
import org.pgpainless.authentication.CertificateAuthority;
import org.pgpainless.exception.KeyException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyAccessor;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.util.Passphrase;

/**
 * Options for the encryption process.
 * This class can be used to set encryption parameters, like encryption keys and passphrases, algorithms etc.
 * <p>
 * A typical use might look like follows:
 * <pre>
 * {@code
 * EncryptionOptions opt = new EncryptionOptions();
 * opt.addRecipient(aliceKey, "Alice <alice@wonderland.lit>");
 * opt.addPassphrase(Passphrase.fromPassword("AdditionalDecryptionPassphrase123"));
 * }
 * </pre>
 *<p>
 * To use a custom symmetric encryption algorithm, use {@link #overrideEncryptionAlgorithm(SymmetricKeyAlgorithm)}.
 * This will cause PGPainless to use the provided algorithm for message encryption, instead of negotiating an algorithm
 * by inspecting the provided recipient keys.
 * <p>
 * By default, PGPainless will encrypt to all suitable, encryption capable subkeys on each recipient's certificate.
 * This behavior can be changed per recipient, e.g. by calling
 * <pre>
 * {@code
 * opt.addRecipient(aliceKey, EncryptionOptions.encryptToFirstSubkey());
 * }
 * </pre>
 * when adding the recipient key.
 */
public class EncryptionOptions {

    private final EncryptionPurpose purpose;
    private final Set<PGPKeyEncryptionMethodGenerator> encryptionMethods = new LinkedHashSet<>();
    private final Set<SubkeyIdentifier> encryptionKeys = new LinkedHashSet<>();
    private final Map<SubkeyIdentifier, KeyRingInfo> keyRingInfo = new HashMap<>();
    private final Map<SubkeyIdentifier, KeyAccessor> keyViews = new HashMap<>();
    private final EncryptionKeySelector encryptionKeySelector = encryptToAllCapableSubkeys();

    private SymmetricKeyAlgorithm encryptionAlgorithmOverride = null;

    /**
     * Encrypt to keys both carrying the key flag {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS}
     * or {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE}.
     */
    public EncryptionOptions() {
        this(EncryptionPurpose.ANY);
    }

    public EncryptionOptions(@Nonnull EncryptionPurpose purpose) {
        this.purpose = purpose;
    }

    /**
     * Factory method to create an {@link EncryptionOptions} object which will encrypt for keys
     * which carry either the {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS} or
     * {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE} flag.
     * <p>
     * Use this if you are not sure.
     *
     * @return encryption options
     */
    public static EncryptionOptions get() {
        return new EncryptionOptions();
    }

    /**
     * Factory method to create an {@link EncryptionOptions} object which will encrypt for keys
     * which carry the flag {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS}.
     *
     * @return encryption options
     */
    public static EncryptionOptions encryptCommunications() {
        return new EncryptionOptions(EncryptionPurpose.COMMUNICATIONS);
    }

    /**
     * Factory method to create an {@link EncryptionOptions} object which will encrypt for keys
     * which carry the flag {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE}.
     *
     * @return encryption options
     */
    public static EncryptionOptions encryptDataAtRest() {
        return new EncryptionOptions(EncryptionPurpose.STORAGE);
    }

    /**
     * Identify authenticatable certificates for the given user-ID by querying the {@link CertificateAuthority} for
     * identifiable bindings.
     * Add all acceptable bindings, whose trust amount is larger or equal to the target amount to the list of recipients.
     * @param userId userId
     * @param email if true, treat the user-ID as an email address and match all user-IDs containing the mail address
     * @param authority certificate authority
     * @return encryption options
     */
    public EncryptionOptions addAuthenticatableRecipients(String userId, boolean email, CertificateAuthority authority) {
        return addAuthenticatableRecipients(userId, email, authority, 120);
    }

    /**
     * Identify authenticatable certificates for the given user-ID by querying the {@link CertificateAuthority} for
     * identifiable bindings.
     * Add all acceptable bindings, whose trust amount is larger or equal to the target amount to the list of recipients.
     * @param userId userId
     * @param email if true, treat the user-ID as an email address and match all user-IDs containing the mail address
     * @param authority certificate authority
     * @param targetAmount target amount (120 = fully authenticated, 240 = doubly authenticated,
     *                    60 = partially authenticated...)
     * @return encryption options
     */
    public EncryptionOptions addAuthenticatableRecipients(String userId, boolean email, CertificateAuthority authority, int targetAmount) {
        List<CertificateAuthenticity> identifiedCertificates = authority.lookupByUserId(userId, email, new Date(), targetAmount);
        boolean foundAcceptable = false;
        for (CertificateAuthenticity candidate : identifiedCertificates) {
            if (candidate.isAuthenticated()) {
                addRecipient(candidate.getCertificate());
                foundAcceptable = true;
            }
        }
        if (!foundAcceptable) {
            throw new IllegalArgumentException("Could not identify any trust-worthy certificates for '" + userId + "' and target trust amount " + targetAmount);
        }
        return this;
    }

    /**
     * Add all key rings in the provided {@link Iterable} (e.g. {@link PGPPublicKeyRingCollection}) as recipients.
     *
     * @param keys keys
     * @return this
     */
    public EncryptionOptions addRecipients(@Nonnull Iterable<PGPPublicKeyRing> keys) {
        if (!keys.iterator().hasNext()) {
            throw new IllegalArgumentException("Set of recipient keys cannot be empty.");
        }
        for (PGPPublicKeyRing key : keys) {
            addRecipient(key);
        }
        return this;
    }

    /**
     * Add all key rings in the provided {@link Iterable} (e.g. {@link PGPPublicKeyRingCollection}) as recipients.
     * Per key ring, the selector is applied to select one or more encryption subkeys.
     *
     * @param keys keys
     * @param selector encryption key selector
     * @return this
     */
    public EncryptionOptions addRecipients(@Nonnull Iterable<PGPPublicKeyRing> keys, @Nonnull EncryptionKeySelector selector) {
        if (!keys.iterator().hasNext()) {
            throw new IllegalArgumentException("Set of recipient keys cannot be empty.");
        }
        for (PGPPublicKeyRing key : keys) {
            addRecipient(key, selector);
        }
        return this;
    }

    /**
     * Add a recipient by providing a key and recipient user-id.
     * The user-id is used to determine the recipients preferences (algorithms etc.).
     *
     * @param key key ring
     * @param userId user id
     * @return this
     */
    public EncryptionOptions addRecipient(@Nonnull PGPPublicKeyRing key, @Nonnull CharSequence userId) {
        return addRecipient(key, userId, encryptionKeySelector);
    }

    /**
     * Add a recipient by providing a key and recipient user-id, as well as a strategy for selecting one or multiple
     * encryption capable subkeys from the key.
     *
     * @param key key
     * @param userId user-id
     * @param encryptionKeySelectionStrategy strategy to select one or more encryption subkeys to encrypt to
     * @return this
     */
    public EncryptionOptions addRecipient(@Nonnull PGPPublicKeyRing key,
                                          @Nonnull CharSequence userId,
                                          @Nonnull EncryptionKeySelector encryptionKeySelectionStrategy) {
        KeyRingInfo info = new KeyRingInfo(key, new Date());

        List<PGPPublicKey> encryptionSubkeys = encryptionKeySelectionStrategy
                .selectEncryptionSubkeys(info.getEncryptionSubkeys(userId.toString(), purpose));
        if (encryptionSubkeys.isEmpty()) {
            throw new KeyException.UnacceptableEncryptionKeyException(OpenPgpFingerprint.of(key));
        }

        for (PGPPublicKey encryptionSubkey : encryptionSubkeys) {
            SubkeyIdentifier keyId = new SubkeyIdentifier(key, encryptionSubkey.getKeyID());
            keyRingInfo.put(keyId, info);
            keyViews.put(keyId, new KeyAccessor.ViaUserId(info, keyId, userId.toString()));
            addRecipientKey(key, encryptionSubkey, false);
        }

        return this;
    }

    /**
     * Add a recipient by providing a key.
     *
     * @param key key ring
     * @return this
     */
    public EncryptionOptions addRecipient(@Nonnull PGPPublicKeyRing key) {
        return addRecipient(key, encryptionKeySelector);
    }

    /**
     * Add a recipient by providing a key and an encryption key selection strategy.
     *
     * @param key key ring
     * @param encryptionKeySelectionStrategy strategy used to select one or multiple encryption subkeys.
     * @return this
     */
    public EncryptionOptions addRecipient(@Nonnull PGPPublicKeyRing key,
                                          @Nonnull EncryptionKeySelector encryptionKeySelectionStrategy) {
        return addAsRecipient(key, encryptionKeySelectionStrategy, false);
    }

    /**
     * Add a certificate as hidden recipient.
     * The recipients key-id will be obfuscated by setting a wildcard key ID.
     *
     * @param key recipient key
     * @return this
     */
    public EncryptionOptions addHiddenRecipient(@Nonnull PGPPublicKeyRing key) {
        return addHiddenRecipient(key, encryptionKeySelector);
    }

    /**
     * Add a certificate as hidden recipient, using the provided {@link EncryptionKeySelector} to select recipient subkeys.
     * The recipients key-ids will be obfuscated by setting a wildcard key ID instead.
     *
     * @param key recipient key
     * @param encryptionKeySelectionStrategy strategy to select recipient (sub) keys.
     * @return this
     */
    public EncryptionOptions addHiddenRecipient(PGPPublicKeyRing key, EncryptionKeySelector encryptionKeySelectionStrategy) {
        return addAsRecipient(key, encryptionKeySelectionStrategy, true);
    }

    private EncryptionOptions addAsRecipient(PGPPublicKeyRing key, EncryptionKeySelector encryptionKeySelectionStrategy, boolean wildcardKeyId) {
        Date evaluationDate = new Date();
        KeyRingInfo info;
        info = new KeyRingInfo(key, evaluationDate);

        Date primaryKeyExpiration;
        try {
            primaryKeyExpiration = info.getPrimaryKeyExpirationDate();
        } catch (NoSuchElementException e) {
            throw new KeyException.UnacceptableSelfSignatureException(OpenPgpFingerprint.of(key));
        }
        if (primaryKeyExpiration != null && primaryKeyExpiration.before(evaluationDate)) {
            throw new KeyException.ExpiredKeyException(OpenPgpFingerprint.of(key), primaryKeyExpiration);
        }

        List<PGPPublicKey> encryptionSubkeys = encryptionKeySelectionStrategy
                .selectEncryptionSubkeys(info.getEncryptionSubkeys(purpose));
        if (encryptionSubkeys.isEmpty()) {
            throw new KeyException.UnacceptableEncryptionKeyException(OpenPgpFingerprint.of(key));
        }

        for (PGPPublicKey encryptionSubkey : encryptionSubkeys) {
            SubkeyIdentifier keyId = new SubkeyIdentifier(key, encryptionSubkey.getKeyID());
            keyRingInfo.put(keyId, info);
            keyViews.put(keyId, new KeyAccessor.ViaKeyId(info, keyId));
            addRecipientKey(key, encryptionSubkey, wildcardKeyId);
        }

        return this;
    }

    private void addRecipientKey(@Nonnull PGPPublicKeyRing keyRing,
                                 @Nonnull PGPPublicKey key,
                                 boolean wildcardKeyId) {
        encryptionKeys.add(new SubkeyIdentifier(keyRing, key.getKeyID()));
        PublicKeyKeyEncryptionMethodGenerator encryptionMethod = ImplementationFactory
                .getInstance().getPublicKeyKeyEncryptionMethodGenerator(key);
        encryptionMethod.setUseWildcardKeyID(wildcardKeyId);
        addEncryptionMethod(encryptionMethod);
    }

    /**
     * Add a symmetric passphrase which the message will be encrypted to.
     *
     * @param passphrase passphrase
     * @return this
     */
    public EncryptionOptions addPassphrase(@Nonnull Passphrase passphrase) {
        if (passphrase.isEmpty()) {
            throw new IllegalArgumentException("Passphrase must not be empty.");
        }
        PBEKeyEncryptionMethodGenerator encryptionMethod = ImplementationFactory
                .getInstance().getPBEKeyEncryptionMethodGenerator(passphrase);
        return addEncryptionMethod(encryptionMethod);
    }

    /**
     * Add an {@link PGPKeyEncryptionMethodGenerator} which will be used to encrypt the message.
     * Method generators are either {@link PBEKeyEncryptionMethodGenerator} (passphrase)
     * or {@link PGPKeyEncryptionMethodGenerator} (public key).
     *
     * This method is intended for advanced users to allow encryption for specific subkeys.
     * This can come in handy for example if data needs to be encrypted to a subkey that's ignored by PGPainless.
     *
     * @param encryptionMethod encryption method
     * @return this
     */
    public EncryptionOptions addEncryptionMethod(@Nonnull PGPKeyEncryptionMethodGenerator encryptionMethod) {
        encryptionMethods.add(encryptionMethod);
        return this;
    }

    Set<PGPKeyEncryptionMethodGenerator> getEncryptionMethods() {
        return new HashSet<>(encryptionMethods);
    }

    Map<SubkeyIdentifier, KeyRingInfo> getKeyRingInfo() {
        return new HashMap<>(keyRingInfo);
    }

    Set<SubkeyIdentifier> getEncryptionKeyIdentifiers() {
        return new HashSet<>(encryptionKeys);
    }

    Map<SubkeyIdentifier, KeyAccessor> getKeyViews() {
        return new HashMap<>(keyViews);
    }

    SymmetricKeyAlgorithm getEncryptionAlgorithmOverride() {
        return encryptionAlgorithmOverride;
    }

    /**
     * Override the used symmetric encryption algorithm.
     * The symmetric encryption algorithm is used to encrypt the message itself,
     * while the used symmetric key will be encrypted to all recipients using public key
     * cryptography.
     *
     * If the algorithm is not overridden, a suitable algorithm will be negotiated.
     *
     * @param encryptionAlgorithm encryption algorithm override
     * @return this
     */
    public EncryptionOptions overrideEncryptionAlgorithm(@Nonnull SymmetricKeyAlgorithm encryptionAlgorithm) {
        if (encryptionAlgorithm == SymmetricKeyAlgorithm.NULL) {
            throw new IllegalArgumentException("Plaintext encryption can only be used to denote unencrypted secret keys.");
        }
        this.encryptionAlgorithmOverride = encryptionAlgorithm;
        return this;
    }

    /**
     * Return <pre>true</pre> iff the user specified at least one encryption method,
     * <pre>false</pre> otherwise.
     *
     * @return encryption methods is not empty
     */
    public boolean hasEncryptionMethod() {
        return !encryptionMethods.isEmpty();
    }

    public interface EncryptionKeySelector {
        List<PGPPublicKey> selectEncryptionSubkeys(@Nonnull List<PGPPublicKey> encryptionCapableKeys);
    }

    /**
     * Only encrypt to the first valid encryption capable subkey we stumble upon.
     *
     * @return encryption key selector
     */
    public static EncryptionKeySelector encryptToFirstSubkey() {
        return new EncryptionKeySelector() {
            @Override
            public List<PGPPublicKey> selectEncryptionSubkeys(@Nonnull List<PGPPublicKey> encryptionCapableKeys) {
                return encryptionCapableKeys.isEmpty() ? Collections.emptyList() : Collections.singletonList(encryptionCapableKeys.get(0));
            }
        };
    }

    /**
     * Encrypt to any valid, encryption capable subkey on the key ring.
     *
     * @return encryption key selector
     */
    public static EncryptionKeySelector encryptToAllCapableSubkeys() {
        return new EncryptionKeySelector() {
            @Override
            public List<PGPPublicKey> selectEncryptionSubkeys(@Nonnull List<PGPPublicKey> encryptionCapableKeys) {
                return encryptionCapableKeys;
            }
        };
    }

    // TODO: Create encryptToBestSubkey() method
}
