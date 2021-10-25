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
import org.pgpainless.signature.subpackets.SignatureSubpacketGeneratorWrapper;

public abstract class AbstractSignatureBuilder<B extends AbstractSignatureBuilder<B>> {
    protected final PGPPrivateKey privateSigningKey;
    protected final PGPPublicKey publicSigningKey;

    protected HashAlgorithm hashAlgorithm;
    protected SignatureType signatureType;

    protected SignatureSubpacketGeneratorWrapper unhashedSubpackets;
    protected SignatureSubpacketGeneratorWrapper hashedSubpackets;

    public AbstractSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        if (!isValidSignatureType(signatureType)) {
            throw new IllegalArgumentException("Invalid signature type.");
        }
        this.signatureType = signatureType;
        this.privateSigningKey = UnlockSecretKey.unlockSecretKey(signingKey, protector);
        this.publicSigningKey = signingKey.getPublicKey();
        this.hashAlgorithm = negotiateHashAlgorithm(publicSigningKey);

        unhashedSubpackets = SignatureSubpacketGeneratorWrapper.createEmptySubpackets();
        hashedSubpackets = SignatureSubpacketGeneratorWrapper.createHashedSubpackets(publicSigningKey);
    }

    public AbstractSignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector, PGPSignature archetypeSignature) throws WrongPassphraseException {
        SignatureType type = SignatureType.valueOf(archetypeSignature.getSignatureType());
        if (!isValidSignatureType(type)) {
            throw new IllegalArgumentException("Invalid signature type.");
        }
        this.signatureType = SignatureType.valueOf(archetypeSignature.getSignatureType());
        this.privateSigningKey = UnlockSecretKey.unlockSecretKey(certificationKey, protector);
        this.publicSigningKey = certificationKey.getPublicKey();
        this.hashAlgorithm = negotiateHashAlgorithm(publicSigningKey);

        unhashedSubpackets = SignatureSubpacketGeneratorWrapper.refreshUnhashedSubpackets(archetypeSignature);
        hashedSubpackets = SignatureSubpacketGeneratorWrapper.refreshHashedSubpackets(publicSigningKey, archetypeSignature);
    }

    protected HashAlgorithm negotiateHashAlgorithm(PGPPublicKey publicKey) {
        Set<HashAlgorithm> hashAlgorithmPreferences = OpenPgpKeyAttributeUtil.getOrGuessPreferredHashAlgorithms(publicKey);
        return HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(PGPainless.getPolicy())
                .negotiateHashAlgorithm(hashAlgorithmPreferences);
    }

    public B setSignatureType(SignatureType type) {
        if (!isValidSignatureType(type)) {
            throw new IllegalArgumentException("Invalid signature type: " + type);
        }
        this.signatureType = type;
        return (B) this;
    }

    protected PGPSignatureGenerator buildAndInitSignatureGenerator() throws PGPException {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        publicSigningKey.getAlgorithm(), hashAlgorithm.getAlgorithmId()
                )
        );
        generator.setUnhashedSubpackets(unhashedSubpackets.getGenerator().generate());
        generator.setHashedSubpackets(hashedSubpackets.getGenerator().generate());
        generator.init(signatureType.getCode(), privateSigningKey);
        return generator;
    }

    protected abstract boolean isValidSignatureType(SignatureType type);
}
