/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.util.Passphrase;

public class UnlockSecretKey {

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector protector)
            throws WrongPassphraseException {
        try {
            PBESecretKeyDecryptor decryptor = protector.getDecryptor(secretKey.getKeyID());
            return secretKey.extractPrivateKey(decryptor);
        } catch (PGPException e) {
            throw new WrongPassphraseException(secretKey.getKeyID(), e);
        }
    }

    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector2 protector) throws WrongPassphraseException {
        try {
            PBESecretKeyDecryptor decryptor = protector.getDecryptor(secretKey);
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
