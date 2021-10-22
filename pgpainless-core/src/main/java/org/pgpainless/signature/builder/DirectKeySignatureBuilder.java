// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public class DirectKeySignatureBuilder extends AbstractSignatureBuilder<DirectKeySignatureBuilder> {

    public DirectKeySignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector, PGPSignature archetypeSignature) throws WrongPassphraseException {
        super(certificationKey, protector, archetypeSignature);
    }

    public DirectKeySignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector) throws WrongPassphraseException {
        super(signatureType, signingKey, protector);
    }

    public SelfSignatureSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public SelfSignatureSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public PGPSignature build(PGPPublicKey key) throws PGPException {
        return buildAndInitSignatureGenerator()
                .generateCertification(key);
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        return type == SignatureType.DIRECT_KEY;
    }
}
