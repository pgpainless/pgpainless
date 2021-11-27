// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;

/**
 * Certification signature builder used to certify other users keys.
 */
public class ThirdPartyCertificationSignatureBuilder extends AbstractSignatureBuilder<ThirdPartyCertificationSignatureBuilder> {

    /**
     * Create a new certification signature builder.
     * This constructor uses {@link SignatureType#GENERIC_CERTIFICATION} as signature type.
     *
     * @param signingKey our own certification key
     * @param protector protector to unlock the certification key
     * @throws WrongPassphraseException in case of a wrong passphrase
     */
    public ThirdPartyCertificationSignatureBuilder(PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        this(SignatureType.GENERIC_CERTIFICATION, signingKey, protector);
    }

    /**
     * Create a new certification signature builder.
     *
     * @param signatureType type of certification
     * @param signingKey our own certification key
     * @param protector protector to unlock the certification key
     * @throws WrongPassphraseException in case of a wrong passphrase
     */
    public ThirdPartyCertificationSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        super(signatureType, signingKey, protector);
    }

    /**
     * Create a new certification signature builder.
     *
     * @param signingKey our own certification key
     * @param protector protector to unlock the certification key
     * @param archetypeSignature signature to use as a template for the new signature
     * @throws WrongPassphraseException in case of a wrong passphrase
     */
    public ThirdPartyCertificationSignatureBuilder(
            PGPSecretKey signingKey,
            SecretKeyRingProtector protector,
            PGPSignature archetypeSignature)
            throws WrongPassphraseException {
        super(signingKey, protector, archetypeSignature);
    }

    public CertificationSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public CertificationSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public void applyCallback(@Nullable CertificationSubpackets.Callback callback) {
        if (callback != null) {
            callback.modifyHashedSubpackets(getHashedSubpackets());
            callback.modifyUnhashedSubpackets(getUnhashedSubpackets());
        }
    }

    /**
     * Create a certification signature for the given user-id and the primary key of the given key ring.
     * @param certifiedKey key ring
     * @param userId user-id to certify
     * @return signature
     * @throws PGPException
     */
    public PGPSignature build(PGPPublicKeyRing certifiedKey, String userId) throws PGPException {
        return buildAndInitSignatureGenerator().generateCertification(userId, certifiedKey.getPublicKey());
    }

    /**
     * Create a certification signature for the given user attribute and the primary key of the given key ring.
     * @param certifiedKey key ring
     * @param userAttribute user-attributes to certify
     * @return signature
     * @throws PGPException
     */
    public PGPSignature build(PGPPublicKeyRing certifiedKey, PGPUserAttributeSubpacketVector userAttribute)
            throws PGPException {
        return buildAndInitSignatureGenerator().generateCertification(userAttribute, certifiedKey.getPublicKey());
    }

    @Override
    protected boolean isValidSignatureType(@Nonnull SignatureType type) {
        switch (type) {
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
                return true;
            default:
                return false;
        }
    }
}
