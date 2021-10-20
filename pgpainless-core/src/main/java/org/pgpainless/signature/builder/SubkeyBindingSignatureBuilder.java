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

public class SubkeyBindingSignatureBuilder extends AbstractSignatureBuilder<SubkeyBindingSignatureBuilder> {

    public SubkeyBindingSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector) throws WrongPassphraseException {
        super(signatureType, signingKey, protector);
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        return type == SignatureType.SUBKEY_BINDING;
    }

    public SelfSignatureSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public SelfSignatureSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public PGPSignature build(PGPPublicKey subkey) throws PGPException {
        return buildAndInitSignatureGenerator()
                .generateCertification(publicSigningKey, subkey);
    }
}
