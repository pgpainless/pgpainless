// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator;
import org.pgpainless.exception.KeyException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper;

public final class SigningOptions {

    /**
     * A method of signing.
     */
    public static final class SigningMethod {
        private final PGPSignatureGenerator signatureGenerator;
        private final boolean detached;
        private final HashAlgorithm hashAlgorithm;

        private SigningMethod(@Nonnull PGPSignatureGenerator signatureGenerator,
                              boolean detached,
                              @Nonnull HashAlgorithm hashAlgorithm) {
            this.signatureGenerator = signatureGenerator;
            this.detached = detached;
            this.hashAlgorithm = hashAlgorithm;
        }

        /**
         * Inline-signature method.
         * The resulting signature will be written into the message itself, together with a one-pass-signature packet.
         *
         * @param signatureGenerator signature generator
         * @param hashAlgorithm hash algorithm used to generate the signature
         * @return inline signing method
         */
        public static SigningMethod inlineSignature(@Nonnull PGPSignatureGenerator signatureGenerator,
                                                    @Nonnull HashAlgorithm hashAlgorithm) {
            return new SigningMethod(signatureGenerator, false, hashAlgorithm);
        }

        /**
         * Detached signing method.
         * The resulting signature will not be added to the message, and instead can be distributed separately
         * to the signed message.
         *
         * @param signatureGenerator signature generator
         * @param hashAlgorithm hash algorithm used to generate the signature
         * @return detached signing method
         */
        public static SigningMethod detachedSignature(@Nonnull PGPSignatureGenerator signatureGenerator,
                                                      @Nonnull HashAlgorithm hashAlgorithm) {
            return new SigningMethod(signatureGenerator, true, hashAlgorithm);
        }

        public boolean isDetached() {
            return detached;
        }

        public PGPSignatureGenerator getSignatureGenerator() {
            return signatureGenerator;
        }

        public HashAlgorithm getHashAlgorithm() {
            return hashAlgorithm;
        }
    }

    private final Map<SubkeyIdentifier, SigningMethod> signingMethods = new HashMap<>();
    private HashAlgorithm hashAlgorithmOverride;

    @Nonnull
    public static SigningOptions get() {
        return new SigningOptions();
    }

    /**
     * Sign the message using an inline signature made by the provided signing key.
     *
     * @param signingKeyProtector protector to unlock the signing key
     * @param signingKey key ring containing the signing key
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be unlocked or a signing method cannot be created
     */
    @Nonnull
    public SigningOptions addSignature(@Nonnull SecretKeyRingProtector signingKeyProtector,
                                       @Nonnull PGPSecretKeyRing signingKey)
            throws PGPException {
        return addInlineSignature(signingKeyProtector, signingKey, DocumentSignatureType.BINARY_DOCUMENT);
    }

    /**
     * Add inline signatures with all secret key rings in the provided secret key ring collection.
     *
     * @param secrectKeyDecryptor decryptor to unlock the signing secret keys
     * @param signingKeys collection of signing keys
     * @param signatureType type of signature (binary, canonical text)
     * @return this
     *
     * @throws KeyException if something is wrong with any of the keys
     * @throws PGPException if any of the keys cannot be unlocked or a signing method cannot be created
     */
    @Nonnull
    public SigningOptions addInlineSignatures(@Nonnull SecretKeyRingProtector secrectKeyDecryptor,
                                              @Nonnull Iterable<PGPSecretKeyRing> signingKeys,
                                              @Nonnull DocumentSignatureType signatureType)
            throws KeyException, PGPException {
        for (PGPSecretKeyRing signingKey : signingKeys) {
            addInlineSignature(secrectKeyDecryptor, signingKey, signatureType);
        }
        return this;
    }

    /**
     * Add an inline-signature.
     * Inline signatures are being embedded into the message itself and can be processed in one pass, thanks to the use
     * of one-pass-signature packets.
     *
     * @param secretKeyDecryptor decryptor to unlock the signing secret key
     * @param secretKey signing key
     * @param signatureType type of signature (binary, canonical text)
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     */
    @Nonnull
    public SigningOptions addInlineSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                             @Nonnull PGPSecretKeyRing secretKey,
                                             @Nonnull DocumentSignatureType signatureType)
            throws KeyException, PGPException {
        return addInlineSignature(secretKeyDecryptor, secretKey, null, signatureType);
    }

    /**
     * Add an inline-signature.
     * Inline signatures are being embedded into the message itself and can be processed in one pass, thanks to the use
     * of one-pass-signature packets.
     * <p>
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param secretKeyDecryptor decryptor to unlock the signing secret key
     * @param secretKey signing key
     * @param userId user-id of the signer
     * @param signatureType signature type (binary, canonical text)
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     */
    @Nonnull
    public SigningOptions addInlineSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                             @Nonnull PGPSecretKeyRing secretKey,
                                             @Nullable CharSequence userId,
                                             @Nonnull DocumentSignatureType signatureType)
            throws KeyException, PGPException {
        return addInlineSignature(secretKeyDecryptor, secretKey, userId, signatureType, null);
    }

    /**
     * Add an inline-signature.
     * Inline signatures are being embedded into the message itself and can be processed in one pass, thanks to the use
     * of one-pass-signature packets.
     * <p>
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param secretKeyDecryptor decryptor to unlock the signing secret key
     * @param secretKey signing key
     * @param userId user-id of the signer
     * @param signatureType signature type (binary, canonical text)
     * @param subpacketsCallback callback to modify the hashed and unhashed subpackets of the signature
     * @return this
     *
     * @throws KeyException if the key is invalid
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     */
    @Nonnull
    public SigningOptions addInlineSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                             @Nonnull PGPSecretKeyRing secretKey,
                                             @Nullable CharSequence userId,
                                             @Nonnull DocumentSignatureType signatureType,
                                             @Nullable BaseSignatureSubpackets.Callback subpacketsCallback)
            throws KeyException, PGPException {
        KeyRingInfo keyRingInfo = new KeyRingInfo(secretKey, new Date());
        if (userId != null && !keyRingInfo.isUserIdValid(userId)) {
            throw new KeyException.UnboundUserIdException(
                    OpenPgpFingerprint.of(secretKey),
                    userId.toString(),
                    keyRingInfo.getLatestUserIdCertification(userId),
                    keyRingInfo.getUserIdRevocation(userId)
            );
        }

        List<PGPPublicKey> signingPubKeys = keyRingInfo.getSigningSubkeys();
        if (signingPubKeys.isEmpty()) {
            throw new KeyException.UnacceptableSigningKeyException(OpenPgpFingerprint.of(secretKey));
        }

        for (PGPPublicKey signingPubKey : signingPubKeys) {
            PGPSecretKey signingSecKey = secretKey.getSecretKey(signingPubKey.getKeyID());
            if (signingSecKey == null) {
                throw new KeyException.MissingSecretKeyException(OpenPgpFingerprint.of(secretKey), signingPubKey.getKeyID());
            }
            PGPPrivateKey signingSubkey = UnlockSecretKey.unlockSecretKey(signingSecKey, secretKeyDecryptor);
            Set<HashAlgorithm> hashAlgorithms = userId != null ? keyRingInfo.getPreferredHashAlgorithms(userId)
                    : keyRingInfo.getPreferredHashAlgorithms(signingPubKey.getKeyID());
            HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, PGPainless.getPolicy());
            addSigningMethod(secretKey, signingSubkey, subpacketsCallback, hashAlgorithm, signatureType, false);
        }

        return this;
    }

    /**
     * Add detached signatures with all key rings from the provided secret key ring collection.
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing keys
     * @param signingKeys collection of signing key rings
     * @param signatureType type of the signature (binary, canonical text)
     * @return this
     *
     * @throws KeyException if something is wrong with any of the keys
     * @throws PGPException if any of the keys cannot be validated or unlocked, or if any signing method cannot be created
     */
    @Nonnull
    public SigningOptions addDetachedSignatures(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                                @Nonnull Iterable<PGPSecretKeyRing> signingKeys,
                                                @Nonnull DocumentSignatureType signatureType)
            throws PGPException {
        for (PGPSecretKeyRing signingKey : signingKeys) {
            addDetachedSignature(secretKeyDecryptor, signingKey, signatureType);
        }
        return this;
    }

    /**
     * Create a detached signature.
     * The signature will be of type {@link DocumentSignatureType#BINARY_DOCUMENT}.
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing key
     * @param signingKey signing key
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method can be created
     */
    @Nonnull
    public SigningOptions addDetachedSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                               @Nonnull PGPSecretKeyRing signingKey)
            throws PGPException {
        return addDetachedSignature(secretKeyDecryptor, signingKey, DocumentSignatureType.BINARY_DOCUMENT);
    }

    /**
     * Create a detached signature.
     * Detached signatures are not being added into the PGP message itself.
     * Instead, they can be distributed separately to the message.
     * Detached signatures are useful if the data that is being signed shall not be modified (e.g. when signing a file).
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing key
     * @param secretKey signing key
     * @param signatureType type of data that is signed (binary, canonical text)
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method can be created
     */
    @Nonnull
    public SigningOptions addDetachedSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                               @Nonnull PGPSecretKeyRing secretKey,
                                               @Nonnull DocumentSignatureType signatureType)
            throws PGPException {
        return addDetachedSignature(secretKeyDecryptor, secretKey, null, signatureType);
    }

    /**
     * Create a detached signature.
     * Detached signatures are not being added into the PGP message itself.
     * Instead, they can be distributed separately to the message.
     * Detached signatures are useful if the data that is being signed shall not be modified (e.g. when signing a file).
     * <p>
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing key
     * @param secretKey signing key
     * @param userId user-id
     * @param signatureType type of data that is signed (binary, canonical text)
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method can be created
     */
    @Nonnull
    public SigningOptions addDetachedSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                               @Nonnull PGPSecretKeyRing secretKey,
                                               @Nullable CharSequence userId,
                                               @Nonnull DocumentSignatureType signatureType)
            throws PGPException {
        return addDetachedSignature(secretKeyDecryptor, secretKey, userId, signatureType, null);
    }

    /**
     * Create a detached signature.
     * Detached signatures are not being added into the PGP message itself.
     * Instead, they can be distributed separately to the message.
     * Detached signatures are useful if the data that is being signed shall not be modified (e.g. when signing a file).
     * <p>
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing key
     * @param secretKey signing key
     * @param userId user-id
     * @param signatureType type of data that is signed (binary, canonical text)
     * @param subpacketCallback callback to modify hashed and unhashed subpackets of the signature
     * @return this
     *
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method can be created
     */
    @Nonnull
    public SigningOptions addDetachedSignature(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                               @Nonnull PGPSecretKeyRing secretKey,
                                               @Nullable CharSequence userId,
                                               @Nonnull DocumentSignatureType signatureType,
                                               @Nullable BaseSignatureSubpackets.Callback subpacketCallback)
            throws PGPException {
        KeyRingInfo keyRingInfo = new KeyRingInfo(secretKey, new Date());
        if (userId != null && !keyRingInfo.isUserIdValid(userId)) {
            throw new KeyException.UnboundUserIdException(
                    OpenPgpFingerprint.of(secretKey),
                    userId.toString(),
                    keyRingInfo.getLatestUserIdCertification(userId),
                    keyRingInfo.getUserIdRevocation(userId)
            );
        }

        List<PGPPublicKey> signingPubKeys = keyRingInfo.getSigningSubkeys();
        if (signingPubKeys.isEmpty()) {
            throw new KeyException.UnacceptableSigningKeyException(OpenPgpFingerprint.of(secretKey));
        }

        for (PGPPublicKey signingPubKey : signingPubKeys) {
            PGPSecretKey signingSecKey = secretKey.getSecretKey(signingPubKey.getKeyID());
            if (signingSecKey == null) {
                throw new KeyException.MissingSecretKeyException(OpenPgpFingerprint.of(secretKey), signingPubKey.getKeyID());
            }
            PGPPrivateKey signingSubkey = UnlockSecretKey.unlockSecretKey(signingSecKey, secretKeyDecryptor);
            Set<HashAlgorithm> hashAlgorithms = userId != null ? keyRingInfo.getPreferredHashAlgorithms(userId)
                    : keyRingInfo.getPreferredHashAlgorithms(signingPubKey.getKeyID());
            HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, PGPainless.getPolicy());
            addSigningMethod(secretKey, signingSubkey, subpacketCallback, hashAlgorithm, signatureType, true);
        }

        return this;
    }

    private void addSigningMethod(@Nonnull PGPSecretKeyRing secretKey,
                                  @Nonnull PGPPrivateKey signingSubkey,
                                  @Nullable BaseSignatureSubpackets.Callback subpacketCallback,
                                  @Nonnull HashAlgorithm hashAlgorithm,
                                  @Nonnull DocumentSignatureType signatureType,
                                  boolean detached)
            throws PGPException {
        SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(secretKey, signingSubkey.getKeyID());
        PGPSecretKey signingSecretKey = secretKey.getSecretKey(signingSubkey.getKeyID());
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.requireFromId(signingSecretKey.getPublicKey().getAlgorithm());
        int bitStrength = signingSecretKey.getPublicKey().getBitStrength();
        if (!PGPainless.getPolicy().getPublicKeyAlgorithmPolicy().isAcceptable(publicKeyAlgorithm, bitStrength)) {
            throw new KeyException.UnacceptableSigningKeyException(
                    new KeyException.PublicKeyAlgorithmPolicyException(
                            OpenPgpFingerprint.of(secretKey), signingSecretKey.getKeyID(), publicKeyAlgorithm, bitStrength));
        }

        PGPSignatureGenerator generator = createSignatureGenerator(signingSubkey, hashAlgorithm, signatureType);

        // Subpackets
        SignatureSubpackets hashedSubpackets = SignatureSubpackets.createHashedSubpackets(signingSecretKey.getPublicKey());
        SignatureSubpackets unhashedSubpackets = SignatureSubpackets.createEmptySubpackets();
        if (subpacketCallback != null) {
            subpacketCallback.modifyHashedSubpackets(hashedSubpackets);
            subpacketCallback.modifyUnhashedSubpackets(unhashedSubpackets);
        }
        generator.setHashedSubpackets(SignatureSubpacketsHelper.toVector(hashedSubpackets));
        generator.setUnhashedSubpackets(SignatureSubpacketsHelper.toVector(unhashedSubpackets));

        SigningMethod signingMethod = detached ?
                SigningMethod.detachedSignature(generator, hashAlgorithm) :
                SigningMethod.inlineSignature(generator, hashAlgorithm);
        signingMethods.put(signingKeyIdentifier, signingMethod);
    }

    /**
     * Negotiate, which hash algorithm to use.
     * <p>
     * This method gives the highest priority to the algorithm override, which can be set via {@link #overrideHashAlgorithm(HashAlgorithm)}.
     * After that, the signing keys hash algorithm preferences are iterated to find the first acceptable algorithm.
     * Lastly, should no acceptable algorithm be found, the {@link Policy Policies} default signature hash algorithm is
     * used as a fallback.
     *
     * @param preferences preferences
     * @param policy policy
     * @return selected hash algorithm
     */
    @Nonnull
    private HashAlgorithm negotiateHashAlgorithm(@Nonnull Set<HashAlgorithm> preferences,
                                                 @Nonnull Policy policy) {
        if (hashAlgorithmOverride != null) {
            return hashAlgorithmOverride;
        }

        return HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(policy)
                .negotiateHashAlgorithm(preferences);
    }

    @Nonnull
    private PGPSignatureGenerator createSignatureGenerator(@Nonnull PGPPrivateKey privateKey,
                                                           @Nonnull HashAlgorithm hashAlgorithm,
                                                           @Nonnull DocumentSignatureType signatureType)
            throws PGPException {
        int publicKeyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        PGPContentSignerBuilder signerBuilder = ImplementationFactory.getInstance()
                .getPGPContentSignerBuilder(publicKeyAlgorithm, hashAlgorithm.getAlgorithmId());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
        signatureGenerator.init(signatureType.getSignatureType().getCode(), privateKey);

        return signatureGenerator;
    }

    /**
     * Return a map of key-ids and signing methods.
     * For internal use.
     *
     * @return signing methods
     */
    @Nonnull
    Map<SubkeyIdentifier, SigningMethod> getSigningMethods() {
        return Collections.unmodifiableMap(signingMethods);
    }

    /**
     * Override hash algorithm negotiation by dictating which hash algorithm needs to be used.
     * If no override has been set, an accetable algorithm will be negotiated instead.
     * <p>
     * Note: To override the hash algorithm for signing, call this method *before* calling
     * {@link #addInlineSignature(SecretKeyRingProtector, PGPSecretKeyRing, DocumentSignatureType)} or
     * {@link #addDetachedSignature(SecretKeyRingProtector, PGPSecretKeyRing, DocumentSignatureType)}.
     *
     * @param hashAlgorithmOverride override hash algorithm
     * @return this
     */
    @Nonnull
    public SigningOptions overrideHashAlgorithm(@Nonnull HashAlgorithm hashAlgorithmOverride) {
        this.hashAlgorithmOverride = hashAlgorithmOverride;
        return this;
    }

    /**
     * Return the hash algorithm override (or null if no override is set).
     *
     * @return hash algorithm override
     */
    @Nullable
    public HashAlgorithm getHashAlgorithmOverride() {
        return hashAlgorithmOverride;
    }
}
