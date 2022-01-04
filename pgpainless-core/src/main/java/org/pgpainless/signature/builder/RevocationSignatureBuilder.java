// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;

public class RevocationSignatureBuilder extends AbstractSignatureBuilder<RevocationSignatureBuilder> {

    public RevocationSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector) throws PGPException {
        super(signatureType, signingKey, protector);
        getHashedSubpackets().setRevocable(true, false);
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        switch (type) {
            case KEY_REVOCATION:
            case SUBKEY_REVOCATION:
            case CERTIFICATION_REVOCATION:
                return true;
            default:
                return false;
        }
    }

    public RevocationSignatureSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public RevocationSignatureSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public void applyCallback(@Nullable RevocationSignatureSubpackets.Callback callback) {
        if (callback != null) {
            callback.modifyHashedSubpackets(getHashedSubpackets());
            callback.modifyUnhashedSubpackets(getUnhashedSubpackets());
        }
    }

    public PGPSignature build(PGPPublicKey revokeeSubkey) throws PGPException {
        PGPSignatureGenerator signatureGenerator = buildAndInitSignatureGenerator();
        if (signatureType == SignatureType.KEY_REVOCATION) {
            if (!revokeeSubkey.isMasterKey()) {
                throw new IllegalArgumentException("Signature type is KEY_REVOCATION, but provided revokeeSubkey does not appear to be a primary key.");
            }
            return signatureGenerator.generateCertification(publicSigningKey);
        } else {
            return signatureGenerator.generateCertification(publicSigningKey, revokeeSubkey);
        }
    }

    public PGPSignature build(String revokeeUserId) throws PGPException {
        PGPSignatureGenerator signatureGenerator = buildAndInitSignatureGenerator();
        if (signatureType != SignatureType.CERTIFICATION_REVOCATION) {
            throw new IllegalArgumentException("Signature type is != CERTIFICATION_REVOCATION.");
        }
        return signatureGenerator.generateCertification(revokeeUserId, publicSigningKey);
    }
}
