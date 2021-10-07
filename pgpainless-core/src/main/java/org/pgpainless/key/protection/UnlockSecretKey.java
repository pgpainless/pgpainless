// Copyright 2021 Paul Schaub.
// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.info.KeyInfo;
import org.pgpainless.util.Passphrase;

public final class UnlockSecretKey {

    private UnlockSecretKey() {

    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        try {
            PBESecretKeyDecryptor decryptor = null;
            if (KeyInfo.isEncrypted(secretKey)) {
                decryptor = protector.getDecryptor(secretKey.getKeyID());
            }
            return secretKey.extractPrivateKey(decryptor);
        } catch (PGPException e) {
            throw new WrongPassphraseException(secretKey.getKeyID(), e);
        }
    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, PBESecretKeyDecryptor decryptor) throws WrongPassphraseException {
        try {
            return secretKey.extractPrivateKey(decryptor);
        } catch (PGPException e) {
            throw new WrongPassphraseException(secretKey.getKeyID(), e);
        }
    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, Passphrase passphrase) throws WrongPassphraseException {
        return unlockSecretKey(secretKey, SecretKeyRingProtector.unlockSingleKeyWith(passphrase, secretKey));
    }
}
