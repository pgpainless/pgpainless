// Copyright 2021 Paul Schaub.
// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.pgpainless.exception.KeyIntegrityException;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.info.KeyInfo;
import org.pgpainless.key.util.PublicKeyParameterValidationUtil;
import org.pgpainless.s2k.Passphrase;

public final class UnlockSecretKey {

    private UnlockSecretKey() {

    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector protector)
            throws PGPException, KeyIntegrityException {

        PBESecretKeyDecryptor decryptor = null;
        if (KeyInfo.isEncrypted(secretKey)) {
            decryptor = protector.getDecryptor(secretKey.getKeyID());
        }
        PGPPrivateKey privateKey = unlockSecretKey(secretKey, decryptor);
        return privateKey;
    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, PBESecretKeyDecryptor decryptor)
            throws PGPException {
        PGPPrivateKey privateKey;
        try {
            privateKey = secretKey.extractPrivateKey(decryptor);
        } catch (PGPException e) {
            throw new WrongPassphraseException(secretKey.getKeyID(), e);
        }

        if (privateKey == null) {
            int s2kType = secretKey.getS2K().getType();
            if (s2kType >= 100 && s2kType <= 110) {
                throw new PGPException("Cannot decrypt secret key" + Long.toHexString(secretKey.getKeyID()) + ": " +
                        "Unsupported private S2K usage type " + s2kType);
            }

            throw new PGPException("Cannot decrypt secret key.");
        }

        PublicKeyParameterValidationUtil.verifyPublicKeyParameterIntegrity(privateKey, secretKey.getPublicKey());

        return privateKey;
    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, Passphrase passphrase)
            throws PGPException, KeyIntegrityException {
        return unlockSecretKey(secretKey, SecretKeyRingProtector.unlockSingleKeyWith(passphrase, secretKey));
    }
}
