// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.pgpainless.decryption_verification.CustomPublicKeyDataDecryptorFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 */
public class CachingBcPublicKeyDataDecryptorFactory
        extends BcPublicKeyDataDecryptorFactory
        implements CustomPublicKeyDataDecryptorFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CachingBcPublicKeyDataDecryptorFactory.class);

    private final Map<String, byte[]> cachedSessionKeys = new HashMap<>();
    private final SubkeyIdentifier decryptionKey;

    public CachingBcPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey, SubkeyIdentifier decryptionKey) {
        super(privateKey);
        this.decryptionKey = decryptionKey;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData) throws PGPException {
        byte[] sessionKey = lookupSessionKeyData(secKeyData);
        if (sessionKey == null) {
            LOGGER.debug("Cache miss for encrypted session key " + Hex.toHexString(secKeyData[0]));
            sessionKey = costlyRecoverSessionData(keyAlgorithm, secKeyData);
            cacheSessionKeyData(secKeyData, sessionKey);
        } else {
            LOGGER.debug("Cache hit for encrypted session key " + Hex.toHexString(secKeyData[0]));
        }
        return sessionKey;
    }

    public byte[] costlyRecoverSessionData(int keyAlgorithm, byte[][] secKeyData) throws PGPException {
        return super.recoverSessionData(keyAlgorithm, secKeyData);
    }

    private byte[] lookupSessionKeyData(byte[][] secKeyData) {
        String key = toKey(secKeyData);
        byte[] sessionKey = cachedSessionKeys.get(key);
        return copy(sessionKey);
    }

    private void cacheSessionKeyData(byte[][] secKeyData, byte[] sessionKey) {
        String key = toKey(secKeyData);
        cachedSessionKeys.put(key, copy(sessionKey));
    }

    private static String toKey(byte[][] secKeyData) {
        byte[] sk = secKeyData[0];
        String key = Base64.toBase64String(sk);
        return key;
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
    public SubkeyIdentifier getSubkeyIdentifier() {
        return decryptionKey;
    }
}
