// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPPad
import org.bouncycastle.openpgp.operator.RFC6637Utils
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.RFC6637KDFCalculator
import org.pgpainless.decryption_verification.HardwareSecurity

class YubikeyDataDecryptorFactory(
    callback: HardwareSecurity.DecryptionCallback,
    keyIdentifier: KeyIdentifier,
) : HardwareSecurity.HardwareDataDecryptorFactory(keyIdentifier, callback) {

    companion object {
        @JvmStatic
        fun createDecryptorFromConnection(
            smartCardConnection: SmartCardConnection,
            pubkey: PGPPublicKey
        ): HardwareSecurity.HardwareDataDecryptorFactory {
            val openpgpSession = OpenPgpSession(smartCardConnection)
            val fingerprintBytes = openpgpSession.getData(KeyRef.DEC.fingerprint)
            val decKeyIdentifier = KeyIdentifier(fingerprintBytes)

            if (!decKeyIdentifier.matches(pubkey.keyIdentifier)) {
                throw IllegalArgumentException("Fingerprint mismatch.")
            }

            val isRSAKey = pubkey.algorithm == PublicKeyAlgorithmTags.RSA_GENERAL
                || pubkey.algorithm == PublicKeyAlgorithmTags.RSA_SIGN
                || pubkey.algorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT

            val callback = object : HardwareSecurity.DecryptionCallback {
                override fun decryptSessionKey(
                    keyIdentifier: KeyIdentifier,
                    keyAlgorithm: Int,
                    sessionKeyData: ByteArray,
                    pkeskVersion: Int
                ): ByteArray {
                    // TODO: Move user pin verification somewhere else
                    openpgpSession.verifyUserPin("asdasd".toCharArray(), true)

                    if(isRSAKey) {
                        // easy
                        val decryptedSessionKey = openpgpSession.decrypt(sessionKeyData)
                        return decryptedSessionKey
                    } else {
                        // meh...
                        val ecPubKey: ECDHPublicBCPGKey = pubkey.publicKeyPacket.key as ECDHPublicBCPGKey
                        // split session data into peer key and encrypted session key

                        // peer key
                        val pLen =
                            ((((sessionKeyData[0].toInt() and 0xff) shl 8) + (sessionKeyData[1].toInt() and 0xff)) + 7) / 8
                        checkRange(2 + pLen + 1, sessionKeyData)
                        val pEnc = ByteArray(pLen)
                        System.arraycopy(sessionKeyData, 2, pEnc, 0, pLen)

                        // encrypted session key
                        val keyLen = sessionKeyData[pLen + 2].toInt() and 0xff
                        checkRange(2 + pLen + 1 + keyLen, sessionKeyData)
                        val keyEnc = ByteArray(keyLen)
                        System.arraycopy(sessionKeyData, 2 + pLen + 1, keyEnc, 0, keyLen)

                        // perform ECDH key agreement via the Yubikey
                        val secret = openpgpSession.decrypt(pEnc)

                        // Use the shared key to decrypt the session key
                        val hashAlgorithm: Int = ecPubKey.hashAlgorithm.toInt()
                        val symmetricKeyAlgorithm: Int = ecPubKey.symmetricKeyAlgorithm.toInt()
                        val userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(
                            pubkey.publicKeyPacket,
                            BcKeyFingerprintCalculator(),
                        )
                        val rfc6637KDFCalculator =
                            RFC6637KDFCalculator(
                                BcPGPDigestCalculatorProvider()[hashAlgorithm],
                                symmetricKeyAlgorithm,
                            )
                        val key =
                            KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial))

                        return PGPPad.unpadSessionData(
                            BcPublicKeyDataDecryptorFactory.unwrapSessionData(
                                keyEnc,
                                symmetricKeyAlgorithm,
                                key,
                            ),
                        )
                    }
                }
            }

            return YubikeyDataDecryptorFactory(callback, decKeyIdentifier)
        }
    }

}
