// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;

public class CertificationSignatureBuilder extends AbstractSignatureBuilder<CertificationSignatureBuilder> {

    public CertificationSignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector)
            throws PGPException {
        this(SignatureType.GENERIC_CERTIFICATION, certificationKey, protector);
    }

    public CertificationSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws PGPException {
        super(signatureType, signingKey, protector);
    }

    public CertificationSignatureBuilder(
            PGPSecretKey certificationKey,
            SecretKeyRingProtector protector,
            PGPSignature archetypeSignature)
            throws PGPException {
        super(certificationKey, protector, archetypeSignature);
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

    public PGPSignature build(PGPPublicKey certifiedKey, String userId) throws PGPException {
        return buildAndInitSignatureGenerator().generateCertification(userId, certifiedKey);
    }

    public PGPSignature build(PGPPublicKey certifiedKey, PGPUserAttributeSubpacketVector userAttribute)
            throws PGPException {
        return buildAndInitSignatureGenerator().generateCertification(userAttribute, certifiedKey);
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
