// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import java.util.Set;
import javax.annotation.Nonnull;

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

    protected AbstractSignatureBuilder(SignatureType signatureType,
                                       PGPSecretKey signingKey,
                                       SecretKeyRingProtector protector,
                                       HashAlgorithm hashAlgorithm,
                                       SignatureSubpackets hashedSubpackets,
                                       SignatureSubpackets unhashedSubpackets)
            throws PGPException {
        if (!isValidSignatureType(signatureType)) {
            throw new IllegalArgumentException("Invalid signature type.");
        }
        this.signatureType = signatureType;
        this.privateSigningKey = UnlockSecretKey.unlockSecretKey(signingKey, protector);
        this.publicSigningKey = signingKey.getPublicKey();
        this.hashAlgorithm = hashAlgorithm;
        this.hashedSubpackets = hashedSubpackets;
        this.unhashedSubpackets = unhashedSubpackets;
    }

    public AbstractSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws PGPException {
        this(
                signatureType,
                signingKey,
                protector,
                negotiateHashAlgorithm(signingKey.getPublicKey()),
                SignatureSubpackets.createHashedSubpackets(signingKey.getPublicKey()),
                SignatureSubpackets.createEmptySubpackets()
        );
    }

    public AbstractSignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector, PGPSignature archetypeSignature)
            throws PGPException {
        this(
                SignatureType.valueOf(archetypeSignature.getSignatureType()),
                certificationKey,
                protector,
                negotiateHashAlgorithm(certificationKey.getPublicKey()),
                SignatureSubpackets.refreshHashedSubpackets(certificationKey.getPublicKey(), archetypeSignature),
                SignatureSubpackets.refreshUnhashedSubpackets(archetypeSignature)
        );
    }

    /**
     * Negotiate a {@link HashAlgorithm} to be used when creating the signature.
     *
     * @param publicKey signing public key
     * @return hash algorithm
     */
    protected static HashAlgorithm negotiateHashAlgorithm(PGPPublicKey publicKey) {
        Set<HashAlgorithm> hashAlgorithmPreferences = OpenPgpKeyAttributeUtil.getOrGuessPreferredHashAlgorithms(publicKey);
        return HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(PGPainless.getPolicy())
                .negotiateHashAlgorithm(hashAlgorithmPreferences);
    }

    public B overrideHashAlgorithm(@Nonnull HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return (B) this;
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
     *
     * @throws PGPException if the signature generator cannot be initialized
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
