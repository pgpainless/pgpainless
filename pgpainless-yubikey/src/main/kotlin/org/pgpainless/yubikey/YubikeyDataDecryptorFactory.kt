// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.OpenPgpSession
import java.util.*
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPPad
import org.bouncycastle.openpgp.operator.RFC6637Utils
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.RFC6637KDFCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.pgpainless.bouncycastle.extensions.getCurveName
import org.pgpainless.decryption_verification.HardwareSecurity
import org.pgpainless.key.OpenPgpV4Fingerprint
import org.pgpainless.key.SubkeyIdentifier
import org.slf4j.LoggerFactory

class YubikeyDataDecryptorFactory(
    callback: HardwareSecurity.DecryptionCallback,
    subkeyIdentifier: SubkeyIdentifier,
) : HardwareSecurity.HardwareDataDecryptorFactory(subkeyIdentifier, callback) {

    companion object {

        @JvmStatic val LOGGER = LoggerFactory.getLogger(YubikeyDataDecryptorFactory::class.java)

        val ADMIN_PIN: CharArray = "12345678".toCharArray()
        val USER_PIN: CharArray = "123456".toCharArray()

        @JvmStatic
        fun createDecryptorFromConnection(
            smartCardConnection: SmartCardConnection,
            pubkey: PGPPublicKey
        ): HardwareSecurity.HardwareDataDecryptorFactory {
            val openpgpSession = OpenPgpSession(smartCardConnection)
            val decKeyIdentifier = SubkeyIdentifier(OpenPgpV4Fingerprint(pubkey))

            val isRSAKey =
                pubkey.algorithm == PublicKeyAlgorithmTags.RSA_GENERAL ||
                    pubkey.algorithm == PublicKeyAlgorithmTags.RSA_SIGN ||
                    pubkey.algorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT

            val callback =
                object : HardwareSecurity.DecryptionCallback {
                    override fun decryptSessionKey(
                        keyIdentifier: KeyIdentifier,
                        keyAlgorithm: Int,
                        sessionKeyData: ByteArray,
                        pkeskVersion: Int
                    ): ByteArray {
                        // TODO: Move user pin verification somewhere else
                        openpgpSession.verifyUserPin(USER_PIN, true)

                        LOGGER.debug("Attempt decryption with key {}", keyIdentifier)

                        if (isRSAKey) {
                            // easy
                            LOGGER.debug("Key is RSA key of length {}", pubkey.bitStrength)
                            val decryptedSessionKey = openpgpSession.decrypt(sessionKeyData)
                            smartCardConnection.close()
                            return decryptedSessionKey
                        } else {
                            // meh...
                            val curveName = pubkey.getCurveName()
                            val ecPubKey: ECDHPublicBCPGKey =
                                pubkey.publicKeyPacket.key as ECDHPublicBCPGKey
                            LOGGER.debug("Key is ECDH key over curve $curveName")
                            // split session data into peer key and encrypted session key

                            // peer key
                            val pLen =
                                ((((sessionKeyData[0].toInt() and 0xff) shl 8) +
                                    (sessionKeyData[1].toInt() and 0xff)) + 7) / 8
                            checkRange(2 + pLen + 1, sessionKeyData)
                            val pEnc = ByteArray(pLen)
                            System.arraycopy(sessionKeyData, 2, pEnc, 0, pLen)

                            // encrypted session key
                            val keyLen = sessionKeyData[pLen + 2].toInt() and 0xff
                            checkRange(2 + pLen + 1 + keyLen, sessionKeyData)
                            val keyEnc = ByteArray(keyLen)
                            System.arraycopy(sessionKeyData, 2 + pLen + 1, keyEnc, 0, keyLen)

                            // perform ECDH key agreement via the Yubikey
                            val params = ECNamedCurveTable.getParameterSpec(curveName)
                            val publicPoint = params.curve.decodePoint(pEnc)
                            val peerKey =
                                JcaPGPKeyConverter()
                                    .setProvider(BouncyCastleProvider())
                                    .getPublicKey(
                                        PGPPublicKey(
                                            PublicKeyPacket(
                                                pubkey.version,
                                                PublicKeyAlgorithmTags.ECDH,
                                                Date(),
                                                ECDHPublicBCPGKey(
                                                    ecPubKey.curveOID,
                                                    publicPoint,
                                                    ecPubKey.hashAlgorithm.toInt(),
                                                    ecPubKey.symmetricKeyAlgorithm.toInt(),
                                                ),
                                            ),
                                            BcKeyFingerprintCalculator(),
                                        ),
                                    )

                            val secret =
                                openpgpSession.decrypt(PublicKeyValues.fromPublicKey(peerKey))
                            smartCardConnection.close()

                            // Use the shared key to decrypt the session key
                            val hashAlgorithm: Int = ecPubKey.hashAlgorithm.toInt()
                            val symmetricKeyAlgorithm: Int = ecPubKey.symmetricKeyAlgorithm.toInt()
                            val userKeyingMaterial =
                                RFC6637Utils.createUserKeyingMaterial(
                                    pubkey.publicKeyPacket,
                                    BcKeyFingerprintCalculator(),
                                )
                            val rfc6637KDFCalculator =
                                RFC6637KDFCalculator(
                                    BcPGPDigestCalculatorProvider()[hashAlgorithm],
                                    symmetricKeyAlgorithm,
                                )
                            val key =
                                KeyParameter(
                                    rfc6637KDFCalculator.createKey(secret, userKeyingMaterial))

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
