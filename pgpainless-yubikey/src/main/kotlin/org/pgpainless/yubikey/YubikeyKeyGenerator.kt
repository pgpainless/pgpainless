package org.pgpainless.yubikey

import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpCurve
import com.yubico.yubikit.openpgp.OpenPgpSession
import openpgp.toSecondsPrecision
import org.bouncycastle.bcpg.PublicSubkeyPacket
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.bcpg.SecretSubkeyPacket
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.gnupg.GnuPGDummyKeyUtil
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.algorithm.PublicKeyAlgorithm
import java.util.*

class YubikeyKeyGenerator(private val api: PGPainless) {

    private val converter = JcaPGPKeyConverter().setProvider(BouncyCastleProvider())

    fun generateModernKey(yubikey: Yubikey,
                          adminPin: CharArray,
                          keyVersion: OpenPGPKeyVersion = OpenPGPKeyVersion.v4,
                          creationTime: Date = Date()): OpenPGPKey {
        yubikey.device.openConnection(SmartCardConnection::class.java).use {
            val session = OpenPgpSession(it)
            session.verifyAdminPin(adminPin)

            var pkVal = session.generateEcKey(KeyRef.ATT, OpenPgpCurve.SECP521R1)
            var pubKey = toPGPPublicKey(pkVal, keyVersion, creationTime, PublicKeyAlgorithm.ECDSA)

            val primarykey = toExternalSecretKey(pubKey, yubikey.info)

            pkVal = session.generateEcKey(KeyRef.SIG, OpenPgpCurve.SECP521R1)
            pubKey = toPGPPublicKey(pkVal, keyVersion, creationTime,PublicKeyAlgorithm.ECDSA)

            val signingKey = toSecretSubKey(toExternalSecretKey(pubKey, yubikey.info), yubikey.info)

            pkVal = session.generateEcKey(KeyRef.DEC, OpenPgpCurve.SECP521R1)
            pubKey = toPGPPublicKey(pkVal, keyVersion, creationTime, PublicKeyAlgorithm.ECDH)

            val encryptionKey = toSecretSubKey(toExternalSecretKey(pubKey, yubikey.info), yubikey.info)

            return OpenPGPKey(PGPSecretKeyRing(listOf(primarykey, signingKey, encryptionKey)))
        }
    }

    private fun toPGPPublicKey(pkVal: PublicKeyValues,
                               version: OpenPGPKeyVersion,
                               creationTime: Date,
                               algorithm: PublicKeyAlgorithm
    ): PGPPublicKey {
        return converter.getPGPPublicKey(version.numeric,
            algorithm.algorithmId,
            null,
            pkVal.toPublicKey(),
            creationTime.toSecondsPrecision())
    }

    private fun toExternalSecretKey(pubkey: PGPPublicKey, deviceInfo: DeviceInfo): PGPSecretKey {
        return PGPSecretKey(
            SecretKeyPacket(
                pubkey.publicKeyPacket,
                0,
                0xfc,
                null,
                null,
                GnuPGDummyKeyUtil.serialToBytes(deviceInfo.serialNumber!!)
            ),
            pubkey
        )
    }

    private fun toGnuStubbedSecretKey(pubKey: PGPPublicKey, deviceInfo: DeviceInfo): PGPSecretKey {
        return PGPSecretKey(
            SecretKeyPacket(
                pubKey.publicKeyPacket,
                0,
                SecretKeyPacket.USAGE_SHA1,
                S2K.gnuDummyS2K(S2K.GNUDummyParams.divertToCard()),
                null,
                GnuPGDummyKeyUtil.serialToBytes(deviceInfo.serialNumber!!)
            ),
            pubKey)
    }

    private fun toSecretSubKey(
        key: PGPSecretKey,
        deviceInfo: DeviceInfo,
        fingerPrintCalculator: KeyFingerPrintCalculator = api.implementation.keyFingerPrintCalculator()
    ): PGPSecretKey {
        val pubSubKey = PGPPublicKey(
            PublicSubkeyPacket(
                key.publicKey.version,
                key.publicKey.algorithm,
                key.publicKey.creationTime,
                key.publicKey.publicKeyPacket.key),
            fingerPrintCalculator)
        return PGPSecretKey(
            SecretSubkeyPacket(
                pubSubKey.publicKeyPacket,
                0,
                0xfc,
                null,
                null,
                GnuPGDummyKeyUtil.serialToBytes(deviceInfo.serialNumber!!)),
            pubSubKey
        )
    }
}
