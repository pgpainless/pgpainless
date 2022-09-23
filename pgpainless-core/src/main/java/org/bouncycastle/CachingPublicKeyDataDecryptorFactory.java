// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Base64;

import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of the {@link PublicKeyDataDecryptorFactory} which caches decrypted session keys.
 * That way, if a message needs to be decrypted multiple times, expensive private key operations can be omitted.
 *
 * This implementation changes the behavior or {@link #recoverSessionData(int, byte[][])} to first return any
 * cache hits.
 * If no hit is found, the method call is delegated to the underlying {@link PublicKeyDataDecryptorFactory}.
 * The result of that is then placed in the cache and returned.
 *
 * TODO: Do we also cache invalid session keys?
 */
public class CachingPublicKeyDataDecryptorFactory implements PublicKeyDataDecryptorFactory {

    private final Map<String, byte[]> cachedSessionKeys = new HashMap<>();
    private final PublicKeyDataDecryptorFactory factory;

    public CachingPublicKeyDataDecryptorFactory(PublicKeyDataDecryptorFactory factory) {
        this.factory = factory;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData) throws PGPException {
        byte[] sessionKey = lookup(secKeyData);
        if (sessionKey == null) {
            sessionKey = factory.recoverSessionData(keyAlgorithm, secKeyData);
            cache(secKeyData, sessionKey);
        }
        return sessionKey;
    }

    private byte[] lookup(byte[][] secKeyData) {
        byte[] sk = secKeyData[0];
        String key = Base64.toBase64String(sk);
        byte[] sessionKey = cachedSessionKeys.get(key);
        return copy(sessionKey);
    }

    private void cache(byte[][] secKeyData, byte[] sessionKey) {
        byte[] sk = secKeyData[0];
        String key = Base64.toBase64String(sk);
        cachedSessionKeys.put(key, copy(sessionKey));
    }

    private static byte[] copy(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, copy.length);
        return copy;
    }

    public void clear() {
        cachedSessionKeys.clear();
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key) throws PGPException {
        return null;
    }
}
