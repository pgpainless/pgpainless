/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

public class KeyRingUtils {

    /**
     * Return the primary {@link PGPSecretKey} from the provided {@link PGPSecretKeyRing}.
     * If it has no primary secret key, throw a {@link NoSuchElementException}.
     *
     * @param secretKeys secret keys
     * @return primary secret key
     */
    public static PGPSecretKey requirePrimarySecretKeyFrom(PGPSecretKeyRing secretKeys) {
        PGPSecretKey primarySecretKey = getPrimarySecretKeyFrom(secretKeys);
        if (primarySecretKey == null) {
            throw new NoSuchElementException("Provided PGPSecretKeyRing has no primary secret key.");
        }
        return primarySecretKey;
    }

    /**
     * Return the primary {@link PGPSecretKey} from the provided {@link PGPSecretKeyRing} or null if it has none.
     *
     * @param secretKeys secret key ring
     * @return primary secret key
     */
    public static PGPSecretKey getPrimarySecretKeyFrom(PGPSecretKeyRing secretKeys) {
        PGPSecretKey secretKey = secretKeys.getSecretKey();
        if (secretKey.isMasterKey()) {
            return secretKey;
        }
        return null;
    }

    /**
     * Return the primary {@link PGPPublicKey} from the provided key ring.
     * Throws a {@link NoSuchElementException} if the key ring has no primary public key.
     *
     * @param keyRing key ring
     * @return primary public key
     */
    public static PGPPublicKey requirePrimaryPublicKeyFrom(PGPKeyRing keyRing) {
        PGPPublicKey primaryPublicKey = getPrimaryPublicKeyFrom(keyRing);
        if (primaryPublicKey == null) {
            throw new NoSuchElementException("Provided PGPKeyRing has no primary public key.");
        }
        return primaryPublicKey;
    }

    /**
     * Return the primary {@link PGPPublicKey} from the provided key ring or null if it has none.
     *
     * @param keyRing key ring
     * @return primary public key
     */
    public static PGPPublicKey getPrimaryPublicKeyFrom(PGPKeyRing keyRing) {
        PGPPublicKey primaryPublicKey = keyRing.getPublicKey();
        if (primaryPublicKey.isMasterKey()) {
            return primaryPublicKey;
        }
        return null;
    }

    public static PGPPublicKey getPublicKeyFrom(PGPKeyRing keyRing, long subKeyId) {
        return keyRing.getPublicKey(subKeyId);
    }

    public static PGPPublicKey requirePublicKeyFrom(PGPKeyRing keyRing, long subKeyId) {
        PGPPublicKey publicKey = getPublicKeyFrom(keyRing, subKeyId);
        if (publicKey == null) {
            throw new IllegalArgumentException("KeyRing does not contain public key with keyID " + Long.toHexString(subKeyId));
        }
        return publicKey;
    }

    public static PGPSecretKey requireSecretKeyFrom(PGPSecretKeyRing keyRing, long subKeyId) {
        PGPSecretKey secretKey = keyRing.getSecretKey(subKeyId);
        if (secretKey == null) {
            throw new IllegalArgumentException("KeyRing does not contain secret key with keyID " + Long.toHexString(subKeyId));
        }
        return secretKey;
    }

    /**
     * Extract a {@link PGPPublicKeyRing} containing all public keys from the provided {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret key ring
     * @return public key ring
     */
    public static PGPPublicKeyRing publicKeyRingFrom(PGPSecretKeyRing secretKeys) {
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeys.getPublicKeys();
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeyList);
        return publicKeyRing;
    }

    /**
     * Unlock a {@link PGPSecretKey} and return the resulting {@link PGPPrivateKey}.
     *
     * @param secretKey secret key
     * @param protector protector to unlock the secret key
     * @return private key
     *
     * @throws PGPException if something goes wrong (eg. wrong passphrase)
     */
    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector protector) throws PGPException {
        return UnlockSecretKey.unlockSecretKey(secretKey, protector);
    }
}
