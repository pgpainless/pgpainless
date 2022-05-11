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
import org.pgpainless.signature.subpackets.CertificationSubpackets;

public class ThirdPartyDirectKeySignatureBuilder extends AbstractSignatureBuilder<ThirdPartyDirectKeySignatureBuilder> {

    public ThirdPartyDirectKeySignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector, PGPSignature archetypeSignature)
            throws PGPException {
        super(certificationKey, protector, archetypeSignature);
    }

    public ThirdPartyDirectKeySignatureBuilder(PGPSecretKey signingKey, SecretKeyRingProtector protector) throws PGPException {
        super(SignatureType.DIRECT_KEY, signingKey, protector);
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

    public PGPSignature build(PGPPublicKey key) throws PGPException {
        PGPSignatureGenerator signatureGenerator = buildAndInitSignatureGenerator();
        if (key.getKeyID() != publicSigningKey.getKeyID()) {
            return signatureGenerator.generateCertification(publicSigningKey, key);
        } else {
            return signatureGenerator.generateCertification(key);
        }
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        return type == SignatureType.DIRECT_KEY;
    }
}
