// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.pgpainless.key.SubkeyIdentifier;

import java.util.HashSet;
import java.util.Set;

/**
 * Enable integration of hardware-backed OpenPGP keys.
 */
public class HardwareSecurity {

    public interface DecryptionCallback {

        /**
         * Delegate decryption of a Public-Key-Encrypted-Session-Key (PKESK) to an external API for dealing with
         * hardware security modules such as smartcards or TPMs.
         *
         * If decryption fails for some reason, a subclass of the {@link HardwareSecurityException} is thrown.
         *
         * @param keyId id of the key
         * @param keyAlgorithm algorithm
         * @param sessionKeyData encrypted session key
         *
         * @return decrypted session key
         * @throws HardwareSecurityException exception
         */
        byte[] decryptSessionKey(long keyId, int keyAlgorithm, byte[] sessionKeyData)
                throws HardwareSecurityException;

    }

    /**
     * Return the key-ids of all keys which appear to be stored on a hardware token / smartcard.
     *
     * @param secretKeys secret keys
     * @return set of keys with S2K type DIVERT_TO_CARD or GNU_DUMMY_S2K
     */
    public static Set<Long> getIdsOfHardwareBackedKeys(PGPSecretKeyRing secretKeys) {
        Set<Long> hardwareBackedKeys = new HashSet<>();
        for (PGPSecretKey secretKey : secretKeys) {
            S2K s2K = secretKey.getS2K();
            if (s2K == null) {
                continue;
            }

            int type = s2K.getType();
            // TODO: Is GNU_DUMMY_S2K appropriate?
            if (type == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD || type == S2K.GNU_DUMMY_S2K) {
                hardwareBackedKeys.add(secretKey.getKeyID());
            }
        }
        return hardwareBackedKeys;
    }

    /**
     * Implementation of {@link PublicKeyDataDecryptorFactory} which delegates decryption of encrypted session keys
     * to a {@link DecryptionCallback}.
     * Users can provide such a callback to delegate decryption of messages to hardware security SDKs.
     */
    public static class HardwareDataDecryptorFactory implements CustomPublicKeyDataDecryptorFactory {

        private final DecryptionCallback callback;
        // luckily we can instantiate the BcPublicKeyDataDecryptorFactory with null as argument.
        private final PublicKeyDataDecryptorFactory factory =
                new BcPublicKeyDataDecryptorFactory(null);
        private SubkeyIdentifier subkey;

        /**
         * Create a new {@link HardwareDataDecryptorFactory}.
         *
         * @param callback decryption callback
         */
        public HardwareDataDecryptorFactory(SubkeyIdentifier subkeyIdentifier, DecryptionCallback callback) {
            this.callback = callback;
            this.subkey = subkeyIdentifier;
        }

        @Override
        public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
                throws PGPException {
            try {
                // delegate decryption to the callback
                return callback.decryptSessionKey(subkey.getSubkeyId(), keyAlgorithm, secKeyData[0]);
            } catch (HardwareSecurityException e) {
                throw new PGPException("Hardware-backed decryption failed.", e);
            }
        }

        @Override
        public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                throws PGPException {
            return factory.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }

        @Override
        public PGPDataDecryptor createDataDecryptor(int aeadAlgorithm, byte[] iv, int chunkSize, int encAlgorithm, byte[] key)
                throws PGPException {
            return factory.createDataDecryptor(aeadAlgorithm, iv, chunkSize, encAlgorithm, key);
        }

        @Override
        public SubkeyIdentifier getSubkeyIdentifier() {
            return subkey;
        }
    }

    public static class HardwareSecurityException
            extends Exception {

    }

}
