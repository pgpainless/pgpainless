// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper;

public abstract class AbstractSignatureBuilder<B extends AbstractSignatureBuilder<B>> {
    protected final PGPPrivateKey privateSigningKey;
    protected final PGPPublicKey publicSigningKey;

    protected HashAlgorithm hashAlgorithm;
    protected SignatureType signatureType;

    protected SignatureSubpackets unhashedSubpackets;
    protected SignatureSubpackets hashedSubpackets;

    public AbstractSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        if (!isValidSignatureType(signatureType)) {
            throw new IllegalArgumentException("Invalid signature type.");
        }
        this.signatureType = signatureType;
        this.privateSigningKey = UnlockSecretKey.unlockSecretKey(signingKey, protector);
        this.publicSigningKey = signingKey.getPublicKey();
        this.hashAlgorithm = negotiateHashAlgorithm(publicSigningKey);

        unhashedSubpackets = new SignatureSubpackets();
        // Prepopulate hashed subpackets with default values (key-id etc.)
        hashedSubpackets = SignatureSubpackets.createHashedSubpackets(publicSigningKey);
    }

    public AbstractSignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector, PGPSignature archetypeSignature)
            throws WrongPassphraseException {
        SignatureType type = SignatureType.valueOf(archetypeSignature.getSignatureType());
        if (!isValidSignatureType(type)) {
            throw new IllegalArgumentException("Invalid signature type.");
        }
        this.signatureType = SignatureType.valueOf(archetypeSignature.getSignatureType());
        this.privateSigningKey = UnlockSecretKey.unlockSecretKey(certificationKey, protector);
        this.publicSigningKey = certificationKey.getPublicKey();
        this.hashAlgorithm = negotiateHashAlgorithm(publicSigningKey);

        unhashedSubpackets = SignatureSubpackets.refreshUnhashedSubpackets(archetypeSignature);
        hashedSubpackets = SignatureSubpackets.refreshHashedSubpackets(publicSigningKey, archetypeSignature);
    }

    /**
     * Negotiate a {@link HashAlgorithm} to be used when creating the signature.
     *
     * @param publicKey signing public key
     * @return hash algorithm
     */
    protected HashAlgorithm negotiateHashAlgorithm(PGPPublicKey publicKey) {
        Set<HashAlgorithm> hashAlgorithmPreferences = OpenPgpKeyAttributeUtil.getOrGuessPreferredHashAlgorithms(publicKey);
        return HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(PGPainless.getPolicy())
                .negotiateHashAlgorithm(hashAlgorithmPreferences);
    }

    /**
     * Set the builders {@link SignatureType}.
     * Note that only those types who are valid for the concrete subclass of this {@link AbstractSignatureBuilder}
     * are allowed. Invalid choices result in an {@link IllegalArgumentException} to be thrown.
     *
     * @param type signature type
     * @return builder
     */
    public B setSignatureType(SignatureType type) {
        if (!isValidSignatureType(type)) {
            throw new IllegalArgumentException("Invalid signature type: " + type);
        }
        this.signatureType = type;
        return (B) this;
    }

    /**
     * Build an instance of {@link PGPSignatureGenerator} initialized with the signing key
     * and with hashed and unhashed subpackets.
     *
     * @return pgp signature generator
     * @throws PGPException
     */
    protected PGPSignatureGenerator buildAndInitSignatureGenerator() throws PGPException {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        publicSigningKey.getAlgorithm(), hashAlgorithm.getAlgorithmId()
                )
        );
        generator.setUnhashedSubpackets(SignatureSubpacketsHelper.toVector(unhashedSubpackets));
        generator.setHashedSubpackets(SignatureSubpacketsHelper.toVector(hashedSubpackets));
        generator.init(signatureType.getCode(), privateSigningKey);
        return generator;
    }

    /**
     * Return true if the given {@link SignatureType} is a valid choice for the concrete implementation
     * of {@link AbstractSignatureBuilder}.
     *
     * @param type type
     * @return return true if valid, false otherwise
     */
    protected abstract boolean isValidSignatureType(SignatureType type);
}
