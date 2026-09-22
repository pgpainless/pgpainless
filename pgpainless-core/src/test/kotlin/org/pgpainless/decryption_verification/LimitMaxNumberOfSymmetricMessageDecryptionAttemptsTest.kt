package org.pgpainless.decryption_verification

import org.bouncycastle.util.io.Streams
import org.junit.jupiter.api.TestTemplate
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.fail
import org.pgpainless.PGPainless
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.util.Passphrase
import org.pgpainless.util.TestAllImplementations
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class LimitMaxNumberOfSymmetricMessageDecryptionAttemptsTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations::class)
    fun testLimitIsExceeded() {
        val api = PGPainless()

        var bOut = ByteArrayOutputStream()
        val mOut = api.generateMessage()
            .onOutputStream(bOut)
            .withOptions(ProducerOptions.encrypt(EncryptionOptions.get(api)
                .addMessagePassphrase(Passphrase.fromPassword("skesk1"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk2"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk3"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk4"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk5"))
            ))
        mOut.write("Hello, World!".toByteArray())
        mOut.close()

        val bIn = ByteArrayInputStream(bOut.toByteArray())
        try {
            api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                    .setMaxSymmetricDecryptionAttempts(16) // 16 < 5*5 = 25
                    .addMessagePassphrase(Passphrase.fromPassword("dud1"))
                    .addMessagePassphrase(Passphrase.fromPassword("dud2"))
                    .addMessagePassphrase(Passphrase.fromPassword("dud3"))
                    .addMessagePassphrase(Passphrase.fromPassword("dud4"))
                    .addMessagePassphrase(Passphrase.fromPassword("skesk5"))) // Match, but out of attempts

            fail { "Expected decryption failure due to exceeded limit of symmetric decryption attempts" }
        } catch (e: MissingDecryptionMethodException) {
            // expected
        }
    }


    @TestTemplate
    @ExtendWith(TestAllImplementations::class)
    fun testUnlimitedAttempts() {
        val api = PGPainless()

        var bOut = ByteArrayOutputStream()
        val mOut = api.generateMessage()
            .onOutputStream(bOut)
            .withOptions(ProducerOptions.encrypt(EncryptionOptions.get(api)
                .addMessagePassphrase(Passphrase.fromPassword("skesk1"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk2"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk3"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk4"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk5"))
            ))
        mOut.write("Hello, World!".toByteArray())
        mOut.close()

        val bIn = ByteArrayInputStream(bOut.toByteArray())
        val mIn = api.processMessage()
            .onInputStream(bIn)
            .withOptions(ConsumerOptions.get(api)
                .setMaxSymmetricDecryptionAttempts(-1) // no limit
                .addMessagePassphrase(Passphrase.fromPassword("dud1"))
                .addMessagePassphrase(Passphrase.fromPassword("dud2"))
                .addMessagePassphrase(Passphrase.fromPassword("dud3"))
                .addMessagePassphrase(Passphrase.fromPassword("dud4"))
                .addMessagePassphrase(Passphrase.fromPassword("skesk5"))) // Match, after 25 attempts
        Streams.drain(mIn)
        mIn.close()
    }
}
