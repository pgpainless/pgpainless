// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public class RevocationSignatureBuilder extends AbstractSignatureBuilder<RevocationSignatureBuilder> {

    public RevocationSignatureBuilder(SignatureType signatureType, PGPSecretKey signingKey, SecretKeyRingProtector protector) throws WrongPassphraseException {
        super(signatureType, signingKey, protector);
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

    public PGPSignature build() {
        return null;
    }
}
