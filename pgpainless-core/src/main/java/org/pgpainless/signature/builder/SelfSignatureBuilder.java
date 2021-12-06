// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public class SelfSignatureBuilder extends AbstractSignatureBuilder<SelfSignatureBuilder> {

    public SelfSignatureBuilder(PGPSecretKey signingKey, SecretKeyRingProtector protector) throws PGPException {
        this(SignatureType.GENERIC_CERTIFICATION, signingKey, protector);
    }

    public SelfSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws PGPException {
        super(signatureType, signingKey, protector);
    }

    public SelfSignatureBuilder(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            PGPSignature oldCertification)
            throws PGPException {
        super(primaryKey, primaryKeyProtector, oldCertification);
    }

    public SelfSignatureSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public SelfSignatureSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public void applyCallback(@Nullable SelfSignatureSubpackets.Callback callback) {
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
    protected boolean isValidSignatureType(SignatureType type) {
        switch (type) {
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
            case DIRECT_KEY:
                return true;
            default:
                return false;
        }
    }
}
