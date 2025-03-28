// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
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
        extends CustomPublicKeyDataDecryptorFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CachingBcPublicKeyDataDecryptorFactory.class);

    private final BcPublicKeyDataDecryptorFactory decryptorFactory;
    private final Map<String, byte[]> cachedSessionKeys = new HashMap<>();
    private final SubkeyIdentifier decryptionKey;

    public CachingBcPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey, SubkeyIdentifier decryptionKey) {
        this.decryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
        this.decryptionKey = decryptionKey;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion) throws PGPException {
        byte[] sessionKey = lookupSessionKeyData(secKeyData);
        if (sessionKey == null) {
            LOGGER.debug("Cache miss for encrypted session key " + Hex.toHexString(secKeyData[0]));
            sessionKey = costlyRecoverSessionData(keyAlgorithm, secKeyData, pkeskVersion);
            cacheSessionKeyData(secKeyData, sessionKey);
        } else {
            LOGGER.debug("Cache hit for encrypted session key " + Hex.toHexString(secKeyData[0]));
        }
        return sessionKey;
    }

    public byte[] costlyRecoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion) throws PGPException {
        return decryptorFactory.recoverSessionData(keyAlgorithm, secKeyData, pkeskVersion);
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

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean b, int i, byte[] bytes) throws PGPException {
        return decryptorFactory.createDataDecryptor(b, i, bytes);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey pgpSessionKey) throws PGPException {
        return decryptorFactory.createDataDecryptor(aeadEncDataPacket, pgpSessionKey);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket symmetricEncIntegrityPacket, PGPSessionKey pgpSessionKey) throws PGPException {
        return decryptorFactory.createDataDecryptor(symmetricEncIntegrityPacket, pgpSessionKey);
    }
}
