// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.signature.PGPContentSignerBuilderProviderFactory

class YubikeySigningTest : YubikeyTest() {

    private val KEY =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: BB2A C3E1 E595 CD05 CFA5  CFE6 EB2E 570D 9EE2 2891\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lNoEaNQmhRMFK4EEACMEIwQBgF429XlvPyJdpfXDxVjVEOJc04wcpfkIoX1CzIjm\n" +
            "daRyv+mz2jfFZlQsCkhw2GsrPRJuKz++1JkspKU+4Vot9dIBD94Y+MoZUgHM4m0t\n" +
            "ItqAdaRcxZWXDpSB0eZH3/lC+VkMUjiqK1Po4qOdZttgpLz+uHcox3gxanjyndAQ\n" +
            "gVQf36sAAgkB/ZgECBHkzUUXyxLBEv9FO4lK02Fo9b2yk4Gu3O7iG84KYEuBWelT\n" +
            "+1VXcmExh1pLvHvZ6nKO4fuyAf9yEB6vh8Ah5LQcQWxpY2UgPGFsaWNlQHBncGFp\n" +
            "bmxlc3Mub3JnPsLAIQQTEwoAUQWCaNQmhQkQ6y5XDZ7iKJEWoQS7KsPh5ZXNBc+l\n" +
            "z+brLlcNnuIokQKbAQUVCgkICwUWAgMBAAQLCQgHCScJAQkCCQMIAQKeCQWJCWYB\n" +
            "gAKZAQAASOMCBA5+qfHTcNXgxQYbK10bTaTkpvJ4du4CijIByfwsi1toCXDMyf0+\n" +
            "7a7AsUR6qLTKF8XZAgvCeHhA8eSELpTCfmdvAgQPwjX7eVtWJ+almb7XHDJTwmV0\n" +
            "Ye8YN3SeQn7BmwHbauvx1Mg6CO7ZnZpQ44FGVoKdF8/BiOUxpppyf5PZFkFCEpze\n" +
            "BGjUJoUSBSuBBAAjBCMEAT8qQFBB+PTh/OTQtZOWttt2H3lkrhLJMuhdVjyW57JE\n" +
            "+VO7f3248FlTFUGQk1pK2+/5ODMRdc7Vwdc5xwQj1vTgAKlRZtOrUCs/XrZXs5S5\n" +
            "IYgCjEzDcH+MxaU2A/L+S2+/VOJ2PrpDdAq3HoiKvfjQBa4yzOKwz/2wlFrOwnFU\n" +
            "Vki+AwEKCQACCQH2m8vDn53COUmwjoaCMKMP5xZcR2dRhqCpK3oQtg+kkQ+wOzJV\n" +
            "ygcT8Dg7Yl0Z7zLMhRnHOcwTZDFQk52GUQNbfhx7wroEGBMKACoFgmjUJoUJEN3S\n" +
            "rkJEJkXRFqEEAh6XCjDVDdDeIypK3dKuQkQmRdECmwwAAGD7AgjhSiFMCMzq3B4L\n" +
            "s/PsXPdFEEZ3yqZmetRMfH5FTdrFkU5wNdPnZW/MyAxF3lAKUlPDQd1t5LU0DAE3\n" +
            "yrf9MZbs0QIIzdbl3cbLNHtFlVLnrSQ5HlcQSQkrmrqjaibBkO9P+RvJEGPVrQp/\n" +
            "uVpkA7I404ZpQJaRdC4y5mwXi+y61M9Im2qc2QRo1CaFEwUrgQQAIwQjBAFybhNP\n" +
            "qpDG2Mffk5qc7A+S//F2AsrqxBo9WKk4xcKBy10CgrpbBz/1IqRrtbpcNaY0vcl5\n" +
            "YczBG/5PtLMTOMXQdAB5nTm7fHtsc3jvKpDZuDXbxwDUG/rYkHIdICGdp0dcfmY4\n" +
            "XEcvg6/0wmb1JNpffGBXCtI0tqir53dhysaeDQllPQACCOiZvj9ozIpvGgCSRbkP\n" +
            "zjQZuLEVEPLQ608ABZFSZJCL7l1Ycj6VSYsG/deoAocukMD36G+obEjhYcGpFp7k\n" +
            "sq9fIG3CwJ0EGBMKAMwFgmjUJoUJEEtN3lgQzJ+7FqEENgGCuh0FnspezqxpS03e\n" +
            "WBDMn7sCmwKhIAQZEwoABgWCaNQmhQAKCRBLTd5YEMyfu4smAgienKF78nQXL6WK\n" +
            "SPu7MC3VesJjjiGHQCB2vzBV+kOFoZJyS0U4R/zH1Q6NPt5XJFUbUyY+xCpWKIgq\n" +
            "ny34nPcHfgIECRVjB5Zs+ZVDK69YYdqhNljjGZtugX9VXrMhPoLVGDyE+9LNo3vR\n" +
            "k8xUs2q2nUASAbG1aovnjZnj0H44lGgKqfEAAK31AgkB/CGspb4IH9gjfhQhVcLl\n" +
            "ypPC+pmRITB3kX2vSTjChvcBcPRJDZtYAdjtIFlmUYrUnlQDxJUOnvG/GZCMqnB5\n" +
            "QewCB2Kcu9foL0O0t6WrXyXQwkimMzx5Kefyu4Vbsj0m8yV5aS4ebPEmxxtWaOu7\n" +
            "1POPHzF3cMIReYhZfiJUEBV19suL\n" +
            "=dA6G\n" +
            "-----END PGP PRIVATE KEY BLOCK-----"

    @Test
    fun signMessageWithYubikey() {
        val device = yubikey.device
        val key = api.readKey().parseKey(KEY)

        val signingKey = key.secretKeys[key.signingKeys[0].keyIdentifier]!!

        val hardwareBasedSigningKey = helper.moveToYubikey(signingKey.unlock(), yubikey, adminPin)
        println(hardwareBasedSigningKey.toAsciiArmoredString())

        val msgOut = ByteArrayOutputStream()
        device.openConnection(SmartCardConnection::class.java).use {
            val connection = it
            val factory =
                object : PGPContentSignerBuilderProviderFactory {
                    override fun create(
                        hashAlgorithm: HashAlgorithm
                    ): PGPContentSignerBuilderProvider {
                        return YubikeyPGPContentSignerBuilderProvider(
                            hashAlgorithm, connection, userPinCallback)
                    }
                }

            val sigOut =
                api.generateMessage()
                    .onOutputStream(msgOut)
                    .withOptions(
                        ProducerOptions.sign(
                            SigningOptions.get()
                                .addInlineSignature(
                                    hardwareBasedSigningKey.signingKeys[0],
                                    factory,
                                    HashAlgorithm.SHA512)))

            sigOut.write("Hello, World!".toByteArray())
            sigOut.close()
            println(msgOut)
        }

        api.processMessage()
            .onInputStream(ByteArrayInputStream(msgOut.toByteArray()))
            .withOptions(
                ConsumerOptions.get().addVerificationCert(hardwareBasedSigningKey.toCertificate()))
            .use {
                it.readAllBytes()
                it.close()
                assertTrue(it.metadata.isVerifiedSigned())
            }
    }
}
