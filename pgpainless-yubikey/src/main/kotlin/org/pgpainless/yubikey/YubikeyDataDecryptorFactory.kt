package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.bcpg.KeyIdentifier
import org.pgpainless.decryption_verification.HardwareSecurity

class YubikeyDataDecryptorFactory(
    smartCardConnection: SmartCardConnection,
    callback: HardwareSecurity.DecryptionCallback,
    keyIdentifier: KeyIdentifier,
) : HardwareSecurity.HardwareDataDecryptorFactory(keyIdentifier, callback) {

    companion object {
        @JvmStatic
        fun createDecryptorFromConnection(smartCardConnection: SmartCardConnection): HardwareSecurity.HardwareDataDecryptorFactory {
            val openpgpSession = OpenPgpSession(smartCardConnection)
            val fingerprintBytes = openpgpSession.getData(KeyRef.DEC.fingerprint)
            val decKeyIdentifier = KeyIdentifier(fingerprintBytes)
            val rsa = true

            val callback = object : HardwareSecurity.DecryptionCallback {
                override fun decryptSessionKey(
                    keyIdentifier: KeyIdentifier,
                    keyAlgorithm: Int,
                    sessionKeyData: ByteArray,
                    pkeskVersion: Int
                ): ByteArray {
                    openpgpSession.verifyUserPin("asdasd".toCharArray(), true)
                    if(rsa) {
                        val decryptedSessionKey = openpgpSession.decrypt(sessionKeyData)

                        return decryptedSessionKey
                    } else {
                        /*
                        val secret = openpgpSession.decrypt(sessionKeyData)
                        val hashAlgorithm: Int = ecPubKey.getHashAlgorithm().toInt()
                        val symmetricKeyAlgorithm: Int = ecPubKey.getSymmetricKeyAlgorithm().toInt()
                        val userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(
                            this.pgpPrivKey.getPublicKeyPacket(),
                            BcKeyFingerprintCalculator(),
                        )
                        val rfc6637KDFCalculator = RFC6637KDFCalculator(
                            BcPGPDigestCalculatorProvider()[hashAlgorithm], symmetricKeyAlgorithm,
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
                         */
                        throw UnsupportedOperationException("ECDH decryption is not yet implemented.")
                    }
                }

            }

            return YubikeyDataDecryptorFactory(smartCardConnection, callback, decKeyIdentifier)
        }
    }

}
