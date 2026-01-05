package org.pgpainless.yubikey

import com.yubico.yubikit.openpgp.KeyRef
import openpgp.toSecondsPrecision
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.api.OpenPGPApi
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.pgpainless.hardware.AdminPinCallback
import java.math.BigInteger
import java.security.KeyPair
import java.security.SecureRandom
import java.util.Date

class YubikeyPGPKeyPairGenerator(
    val api: OpenPGPApi,
    val yubikey: Yubikey,
    val keyRef: KeyRef,
    val adminPinCallback: AdminPinCallback,
    version: Int,
    creationTime: Date = Date().toSecondsPrecision(),
    fingerPrintCalculator: KeyFingerPrintCalculator = api.implementation.keyFingerPrintCalculator()
) : PGPKeyPairGenerator(
    version,
    creationTime,
    SecureRandom(),
    fingerPrintCalculator) {

    override fun generateRsaKeyPair(
        exponent: BigInteger?,
        bitStrength: Int
    ): PGPKeyPair? {
        yubikey.openSession().use {
            val pin = adminPinCallback.provideAdminPin(yubikey.serialNumber)
            it.verifyAdminPin(pin ?: return null)
            val pkVal = it.generateRsaKey(keyRef, bitStrength)
            val keyPair = JcaPGPKeyPair(version, PublicKeyAlgorithmTags.RSA_GENERAL,
                KeyPair(pkVal.toPublicKey(), null), creationTime.toSecondsPrecision())

            it.writeGenerationTime(keyPair.publicKey, keyRef)

            return keyPair
        }
    }

    override fun generateEd25519KeyPair(): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateEd448KeyPair(): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateX25519KeyPair(): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateX448KeyPair(): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateLegacyEd25519KeyPair(): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateLegacyX25519KeyPair(): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateECDHKeyPair(curveOID: ASN1ObjectIdentifier?): PGPKeyPair? {
        TODO("Not yet implemented")
    }

    override fun generateECDSAKeyPair(curveOID: ASN1ObjectIdentifier?): PGPKeyPair? {
        TODO("Not yet implemented")
    }
}
