// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import kotlin.jvm.Throws
import org.bouncycastle.bcpg.AEADEncDataPacket
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.PGPDataDecryptor
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.pgpainless.key.SubkeyIdentifier

/** Enable integration of hardware-backed OpenPGP keys. */
class HardwareSecurity {

    interface DecryptionCallback {

        /**
         * Delegate decryption of a Public-Key-Encrypted-Session-Key (PKESK) to an external API for
         * dealing with hardware security modules such as smartcards or TPMs.
         *
         * If decryption fails for some reason, a subclass of the [HardwareSecurityException] is
         * thrown.
         *
         * @param keyId id of the key
         * @param keyAlgorithm algorithm
         * @param sessionKeyData encrypted session key
         * @param pkeskVersion version of the Public-Key-Encrypted-Session-Key packet (3 or 6)
         * @return decrypted session key
         * @throws HardwareSecurityException exception
         */
        @Throws(HardwareSecurityException::class)
        fun decryptSessionKey(
            keyId: Long,
            keyAlgorithm: Int,
            sessionKeyData: ByteArray,
            pkeskVersion: Int
        ): ByteArray
    }

    /**
     * Implementation of [PublicKeyDataDecryptorFactory] which delegates decryption of encrypted
     * session keys to a [DecryptionCallback]. Users can provide such a callback to delegate
     * decryption of messages to hardware security SDKs.
     */
    class HardwareDataDecryptorFactory(
        override val subkeyIdentifier: SubkeyIdentifier,
        private val callback: DecryptionCallback,
    ) : CustomPublicKeyDataDecryptorFactory() {

        // luckily we can instantiate the BcPublicKeyDataDecryptorFactory with null as argument.
        private val factory: PublicKeyDataDecryptorFactory = BcPublicKeyDataDecryptorFactory(null)

        override fun createDataDecryptor(
            withIntegrityPacket: Boolean,
            encAlgorithm: Int,
            key: ByteArray?
        ): PGPDataDecryptor {
            return factory.createDataDecryptor(withIntegrityPacket, encAlgorithm, key)
        }

        override fun createDataDecryptor(
            aeadEncDataPacket: AEADEncDataPacket?,
            sessionKey: PGPSessionKey?
        ): PGPDataDecryptor {
            return factory.createDataDecryptor(aeadEncDataPacket, sessionKey)
        }

        override fun createDataDecryptor(
            seipd: SymmetricEncIntegrityPacket?,
            sessionKey: PGPSessionKey?
        ): PGPDataDecryptor {
            return factory.createDataDecryptor(seipd, sessionKey)
        }

        override fun recoverSessionData(
            keyAlgorithm: Int,
            secKeyData: Array<out ByteArray>,
            pkeskVersion: Int
        ): ByteArray {
            return try {
                callback.decryptSessionKey(
                    subkeyIdentifier.subkeyId, keyAlgorithm, secKeyData[0], pkeskVersion)
            } catch (e: HardwareSecurityException) {
                throw PGPException("Hardware-backed decryption failed.", e)
            }
        }
    }

    class HardwareSecurityException : Exception()
}
