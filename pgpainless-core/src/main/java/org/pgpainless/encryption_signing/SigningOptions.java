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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator;
import org.pgpainless.exception.KeyCannotSignException;
import org.pgpainless.exception.KeyValidationError;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.policy.Policy;

public final class SigningOptions {

    /**
     * A method of signing.
     */
    public static final class SigningMethod {
        private final PGPSignatureGenerator signatureGenerator;
        private final boolean detached;
        private final HashAlgorithm hashAlgorithm;

        private SigningMethod(PGPSignatureGenerator signatureGenerator, boolean detached, HashAlgorithm hashAlgorithm) {
            this.signatureGenerator = signatureGenerator;
            this.detached = detached;
            this.hashAlgorithm = hashAlgorithm;
        }

        /**
         * Inline-signature method.
         * The resulting signature will be written into the message itself, together with a one-pass-signature packet.
         *
         * @param signatureGenerator signature generator
         * @return inline signing method
         */
        public static SigningMethod inlineSignature(PGPSignatureGenerator signatureGenerator, HashAlgorithm hashAlgorithm) {
            return new SigningMethod(signatureGenerator, false, hashAlgorithm);
        }

        /**
         * Detached signing method.
         * The resulting signature will not be added to the message, and instead can be distributed separately
         * to the signed message.
         *
         * @param signatureGenerator signature generator
         * @return detached signing method
         */
        public static SigningMethod detachedSignature(PGPSignatureGenerator signatureGenerator, HashAlgorithm hashAlgorithm) {
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

    public static SigningOptions get() {
        return new SigningOptions();
    }

    /**
     * Add inline signatures with all secret key rings in the provided secret key ring collection.
     *
     * @param secrectKeyDecryptor decryptor to unlock the signing secret keys
     * @param signingKeys collection of signing keys
     * @param signatureType type of signature (binary, canonical text)
     * @return this
     * @throws KeyValidationError if something is wrong with any of the keys
     * @throws PGPException if any of the keys cannot be unlocked or a signing method cannot be created
     */
    public SigningOptions addInlineSignatures(SecretKeyRingProtector secrectKeyDecryptor,
                                              PGPSecretKeyRingCollection signingKeys,
                                              DocumentSignatureType signatureType)
            throws KeyValidationError, PGPException {
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
     * @throws KeyValidationError if something is wrong with the key
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     * @return this
     */
    public SigningOptions addInlineSignature(SecretKeyRingProtector secretKeyDecryptor,
                                             PGPSecretKeyRing secretKey,
                                             DocumentSignatureType signatureType)
            throws KeyValidationError, PGPException {
        return addInlineSignature(secretKeyDecryptor, secretKey, null, signatureType);
    }

    /**
     * Add an inline-signature.
     * Inline signatures are being embedded into the message itself and can be processed in one pass, thanks to the use
     * of one-pass-signature packets.
     *
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param secretKeyDecryptor decryptor to unlock the signing secret key
     * @param secretKey signing key
     * @param userId user-id of the signer
     * @param signatureType signature type (binary, canonical text)
     * @return this
     * @throws KeyValidationError if the key is invalid
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     */
    public SigningOptions addInlineSignature(SecretKeyRingProtector secretKeyDecryptor,
                                             PGPSecretKeyRing secretKey,
                                             String userId,
                                             DocumentSignatureType signatureType)
            throws KeyValidationError, PGPException {
        KeyRingInfo keyRingInfo = new KeyRingInfo(secretKey, new Date());
        if (userId != null && !keyRingInfo.isUserIdValid(userId)) {
            throw new KeyValidationError(userId, keyRingInfo.getLatestUserIdCertification(userId), keyRingInfo.getUserIdRevocation(userId));
        }

        List<PGPPublicKey> signingPubKeys = keyRingInfo.getSigningSubkeys();
        if (signingPubKeys.isEmpty()) {
            throw new KeyCannotSignException("Key " + new OpenPgpV4Fingerprint(secretKey) + " has no valid signing key.");
        }

        for (PGPPublicKey signingPubKey : signingPubKeys) {
            PGPSecretKey signingSecKey = secretKey.getSecretKey(signingPubKey.getKeyID());
            PGPPrivateKey signingSubkey = UnlockSecretKey.unlockSecretKey(signingSecKey, secretKeyDecryptor);
            Set<HashAlgorithm> hashAlgorithms = keyRingInfo.getPreferredHashAlgorithms(userId, signingPubKey.getKeyID());
            HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, PGPainless.getPolicy());
            addSigningMethod(secretKey, signingSubkey, hashAlgorithm, signatureType, false);
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
     * @throws PGPException if any of the keys cannot be validated or unlocked, or if any signing method cannot be created
     */
    public SigningOptions addDetachedSignatures(SecretKeyRingProtector secretKeyDecryptor,
                                                PGPSecretKeyRingCollection signingKeys,
                                                DocumentSignatureType signatureType)
            throws PGPException {
        for (PGPSecretKeyRing signingKey : signingKeys) {
            addDetachedSignature(secretKeyDecryptor, signingKey, signatureType);
        }
        return this;
    }

    /**
     * Create a detached signature.
     * Detached signatures are not being added into the PGP message itself.
     * Instead they can be distributed separately to the message.
     * Detached signatures are useful if the data that is being signed shall not be modified (eg. when signing a file).
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing key
     * @param secretKey signing key
     * @param signatureType type of data that is signed (binary, canonical text)
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method can be created
     * @return this
     */
    public SigningOptions addDetachedSignature(SecretKeyRingProtector secretKeyDecryptor,
                                               PGPSecretKeyRing secretKey,
                                               DocumentSignatureType signatureType)
            throws PGPException {
        return addDetachedSignature(secretKeyDecryptor, secretKey, null, signatureType);
    }

    /**
     * Create a detached signature.
     * Detached signatures are not being added into the PGP message itself.
     * Instead they can be distributed separately to the message.
     * Detached signatures are useful if the data that is being signed shall not be modified (eg. when signing a file).
     *
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param secretKeyDecryptor decryptor to unlock the secret signing key
     * @param secretKey signing key
     * @param userId user-id
     * @param signatureType type of data that is signed (binary, canonical text)
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method can be created
     * @return this
     */
    public SigningOptions addDetachedSignature(SecretKeyRingProtector secretKeyDecryptor,
                                               PGPSecretKeyRing secretKey,
                                               String userId,
                                               DocumentSignatureType signatureType)
            throws PGPException {
        KeyRingInfo keyRingInfo = new KeyRingInfo(secretKey, new Date());
        if (userId != null && !keyRingInfo.isUserIdValid(userId)) {
            throw new KeyValidationError(userId, keyRingInfo.getLatestUserIdCertification(userId), keyRingInfo.getUserIdRevocation(userId));
        }

        List<PGPPublicKey> signingPubKeys = keyRingInfo.getSigningSubkeys();
        if (signingPubKeys.isEmpty()) {
            throw new KeyCannotSignException("Key has no valid signing key.");
        }

        for (PGPPublicKey signingPubKey : signingPubKeys) {
            PGPSecretKey signingSecKey = secretKey.getSecretKey(signingPubKey.getKeyID());
            PGPPrivateKey signingSubkey = signingSecKey.extractPrivateKey(secretKeyDecryptor.getDecryptor(signingPubKey.getKeyID()));
            Set<HashAlgorithm> hashAlgorithms = keyRingInfo.getPreferredHashAlgorithms(userId, signingPubKey.getKeyID());
            HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, PGPainless.getPolicy());
            addSigningMethod(secretKey, signingSubkey, hashAlgorithm, signatureType, true);
        }

        return this;
    }

    private void addSigningMethod(PGPSecretKeyRing secretKey,
                                  PGPPrivateKey signingSubkey,
                                  HashAlgorithm hashAlgorithm,
                                  DocumentSignatureType signatureType,
                                  boolean detached)
            throws PGPException {
        SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(secretKey, signingSubkey.getKeyID());
        PGPSecretKey signingSecretKey = secretKey.getSecretKey(signingSubkey.getKeyID());
        PGPSignatureGenerator generator = createSignatureGenerator(signingSubkey, hashAlgorithm, signatureType);
        generator.setUnhashedSubpackets(unhashedSubpackets(signingSecretKey).generate());
        SigningMethod signingMethod = detached ?
                SigningMethod.detachedSignature(generator, hashAlgorithm) :
                SigningMethod.inlineSignature(generator, hashAlgorithm);
        signingMethods.put(signingKeyIdentifier, signingMethod);
    }

    /**
     * Negotiate, which hash algorithm to use.
     *
     * This method gives the highest priority to the algorithm override, which can be set via {@link #overrideHashAlgorithm(HashAlgorithm)}.
     * After that, the signing keys hash algorithm preferences are iterated to find the first acceptable algorithm.
     * Lastly, should no acceptable algorithm be found, the {@link Policy Policies} default signature hash algorithm is
     * used as a fallback.
     *
     * @param preferences preferences
     * @param policy policy
     * @return selected hash algorithm
     */
    private HashAlgorithm negotiateHashAlgorithm(Set<HashAlgorithm> preferences, Policy policy) {
        if (hashAlgorithmOverride != null) {
            return hashAlgorithmOverride;
        }

        return HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(policy)
                .negotiateHashAlgorithm(preferences);
    }

    private PGPSignatureGenerator createSignatureGenerator(PGPPrivateKey privateKey,
                                                           HashAlgorithm hashAlgorithm,
                                                           DocumentSignatureType signatureType)
            throws PGPException {
        int publicKeyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        PGPContentSignerBuilder signerBuilder = ImplementationFactory.getInstance()
                .getPGPContentSignerBuilder(publicKeyAlgorithm, hashAlgorithm.getAlgorithmId());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
        signatureGenerator.init(signatureType.getSignatureType().getCode(), privateKey);

        return signatureGenerator;
    }

    private PGPSignatureSubpacketGenerator unhashedSubpackets(PGPSecretKey key) {
        PGPSignatureSubpacketGenerator generator = new PGPSignatureSubpacketGenerator();
        generator.setIssuerKeyID(false, key.getKeyID());
        generator.setIssuerFingerprint(false, key);
        return generator;
    }

    /**
     * Return a map of key-ids and signing methods.
     * For internal use.
     *
     * @return signing methods
     */
    public Map<SubkeyIdentifier, SigningMethod> getSigningMethods() {
        return Collections.unmodifiableMap(signingMethods);
    }

    /**
     * Override hash algorithm negotiation by dictating which hash algorithm needs to be used.
     * If no override has been set, an accetable algorithm will be negotiated instead.
     *
     * Note: To override the hash algorithm for signing, call this method *before* calling
     * {@link #addInlineSignature(SecretKeyRingProtector, PGPSecretKeyRing, DocumentSignatureType)} or
     * {@link #addDetachedSignature(SecretKeyRingProtector, PGPSecretKeyRing, DocumentSignatureType)}.
     *
     * @param hashAlgorithmOverride override hash algorithm
     * @return this
     */
    public SigningOptions overrideHashAlgorithm(HashAlgorithm hashAlgorithmOverride) {
        this.hashAlgorithmOverride = hashAlgorithmOverride;
        return this;
    }

    /**
     * Return the hash algorithm override (or null if no override is set).
     *
     * @return hash algorithm override
     */
    public HashAlgorithm getHashAlgorithmOverride() {
        return hashAlgorithmOverride;
    }
}
