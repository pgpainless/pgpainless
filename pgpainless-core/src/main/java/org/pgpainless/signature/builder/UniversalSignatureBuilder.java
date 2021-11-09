// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpackets;

/**
 * Signature builder without restrictions on subpacket contents.
 */
public class UniversalSignatureBuilder extends AbstractSignatureBuilder<UniversalSignatureBuilder> {

    public UniversalSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        super(signatureType, signingKey, protector);
    }

    public UniversalSignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector, PGPSignature archetypeSignature)
            throws WrongPassphraseException {
        super(certificationKey, protector, archetypeSignature);
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        return true;
    }

    public SignatureSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public SignatureSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public void applyCallback(@Nullable BaseSignatureSubpackets.Callback callback) {
        if (callback != null) {
            callback.modifyHashedSubpackets(getHashedSubpackets());
            callback.modifyUnhashedSubpackets(getUnhashedSubpackets());
        }
    }

    public PGPSignatureGenerator getSignatureGenerator() throws PGPException {
        return buildAndInitSignatureGenerator();
    }
}
