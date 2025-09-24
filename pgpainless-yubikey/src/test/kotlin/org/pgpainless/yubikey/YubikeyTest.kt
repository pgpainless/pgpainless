package org.pgpainless.yubikey

import com.yubico.yubikit.core.keys.PrivateKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.desktop.CompositeDevice
import com.yubico.yubikit.desktop.YubiKitManager
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.gnupg.GnuPGDummyKeyUtil
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.bouncycastle.extensions.toOpenPGPKey
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.ecc.EllipticCurve
import org.pgpainless.key.protection.SecretKeyRingProtector

class YubikeyTest {

    val USER_PIN: CharArray = "123456".toCharArray()
    val ADMIN_PIN: CharArray = "12345678".toCharArray()

    private val KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "Comment: BB2A C3E1 E595 CD05 CFA5  CFE6 EB2E 570D 9EE2 2891\n" +
        "Comment: Alice <alice@pgpainless.org>\n" +
        "\n" +
        "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\n" +
        "1POPHzF3cMIReYhZfiJUEBV19suL\n" +
        "=dA6G\n" +
        "-----END PGP PRIVATE KEY BLOCK-----"
    private val CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "Comment: BB2A C3E1 E595 CD05 CFA5  CFE6 EB2E 570D 9EE2 2891\n" +
        "Comment: Alice <alice@pgpainless.org>\n" +
        "\n" +
        "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\n" +
        "iw==\n" +
        "=Oq+Y\n" +
        "-----END PGP PUBLIC KEY BLOCK-----"

    private val MSG = "-----BEGIN PGP MESSAGE-----\n" +
        "Version: PGPainless\n" +
        "\n" +
        "wcAQBhUEAh6XCjDVDdDeIypK3dKuQkQmRdESBCMEAV9Lm/I5jEe9t8Mdd7Pmk7S0\n" +
        "3q308GnSq640CbhgORysK4+dnRYMzZFphil7dDsKWe2X7RMz7TDiPQhaoro6z0JP\n" +
        "AZMx5eFiL0irdC9qV+0LvSnGJ8CyW3K15mKUomX82unAhquEhLtuPBufAN4bf2ia\n" +
        "EiM85oz2U8CZ2Un48QLldDoHMKOdeAqX1xqFeBrD+ObgNsNfCLoYg4SM/EOUc06x\n" +
        "U78DC23EfOI428Nfvzq1GiqVhtLAYgIJAQMNZthd/Qa2vPy8EaMLXn/NV35v4PzO\n" +
        "39OYkdHRTO6g6OTI4Qf6fpXWoC8GdHIMOHGPMh2hKCXIXPEV0bncfnrUIXk9+miX\n" +
        "7pFaM7kn/YGO48QUtY5ZxJdJAcjZA+vHBws8eDKC5Ajl5VYZrX187MQ+x/JID642\n" +
        "QNsxUocyYwvRZenRQCuUV0vee08iLia/olzVjYQvsPYg6F/wa0KZRat2WMi/ofy9\n" +
        "8C0tMUo31K4v2/z9T58DAR0P8AmLH/+196ijRbJ61U8HdiqYYPz7pevKdRB3N/0b\n" +
        "dKkwF/chL+a/fSaxfAtJF2Zua4iW1OyrsbgIyXADUoS12K056A24yYE6dbMGVdhS\n" +
        "+kQi5FkaOBCe1HVuETfNZ9XYV1312Dlj\n" +
        "=XVu4\n" +
        "-----END PGP MESSAGE-----"

    @Test
    fun test() {
        val api = PGPainless(BcOpenPGPImplementation())
        val key = api.readKey().parseKey(KEY)

        val decKey = key.secretKeys[key.encryptionKeys[0].keyIdentifier]!!
        val msgIn = MSG.byteInputStream()

        val privKey = decKey.pgpSecretKey.extractPrivateKey(null)
        val k = JcaPGPKeyConverter().setProvider(BouncyCastleProvider()).getPrivateKey(privKey)
        val sn = 15472425
        val movedToCard = GnuPGDummyKeyUtil.modify(key)
            .divertPrivateKeysToCard(GnuPGDummyKeyUtil.KeyFilter { it.matchesExplicit(decKey.keyIdentifier) }, byteArrayOf(
                (sn shr 24).toByte(), (sn shr(16)).toByte(), (sn shr(8)).toByte(), sn.toByte()
            )).toOpenPGPKey(api.implementation)
        println(key.toCertificate().toAsciiArmoredString())
        println(MSG)
        val manager = YubiKitManager()
        val device = manager.listAllDevices().entries.find { it.key is CompositeDevice }?.key
            ?: throw IllegalStateException("No Yubikey attached.")

        // Write key
        device.openConnection(SmartCardConnection::class.java).use {
            val connection = it
            val openpgp = OpenPgpSession(connection as SmartCardConnection)
            openpgp.reset()

            openpgp.verifyAdminPin(ADMIN_PIN)

            openpgp.putKey(
                com.yubico.yubikit.openpgp.KeyRef.DEC,
                PrivateKeyValues.fromPrivateKey(k)
            )
            val fp = decKey.pgpPublicKey.fingerprint
            openpgp.setFingerprint(com.yubico.yubikit.openpgp.KeyRef.DEC, fp)
            openpgp.setGenerationTime(
                com.yubico.yubikit.openpgp.KeyRef.DEC,
                (decKey.pgpPublicKey.publicKeyPacket.time.time / 1000).toInt()
            )
        }
        device.openConnection(SmartCardConnection::class.java).use {
            val decFac = YubikeyDataDecryptorFactory.createDecryptorFromConnection(it, decKey.pgpPublicKey)
            val decIn = api.processMessage()
                .onInputStream(msgIn)
                .withOptions(
                    ConsumerOptions.get(api)
                        //.addDecryptionKey(api.readKey().parseKey(KEY))
                        .addCustomDecryptorFactory(decFac)
                )
            val msg = decIn.readAllBytes()
            decIn.close()
            assertEquals("Hello, World!\n", String(msg))
        }
    }
}
