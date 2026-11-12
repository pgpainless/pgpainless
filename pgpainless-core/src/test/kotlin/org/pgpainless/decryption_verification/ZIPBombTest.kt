// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.util.io.StreamOverflowException
import org.bouncycastle.util.io.Streams
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.encryption_signing.ProducerOptions
import java.io.ByteArrayOutputStream
import java.util.Arrays

class ZIPBombTest {

    @Test
    fun `verify that zip bombs are prevented by Policy_maxDecompressionDataSize`() {
        val plain = ByteArray(8 * 1024 * 1024)

        var api = PGPainless.getInstance()
        Arrays.fill(plain, 0.toByte())
        val bOut = ByteArrayOutputStream()
        val compressOut = api.generateMessage()
            .onOutputStream(bOut)
            .withOptions(ProducerOptions.noEncryptionNoSigning()
                .overrideCompressionAlgorithm(CompressionAlgorithm.BZIP2))

        compressOut.write(plain)
        compressOut.close()

        println(bOut)

        var policy = api.algorithmPolicy
            .copy()
            .withMaxDecompressedDataSize(4 * 1024 * 1024)
            .build()
        api = PGPainless(policy)

        val bIn = bOut.toByteArray().inputStream()
        val dIn = api.processMessage()
            .onInputStream(bIn)
            .withOptions(ConsumerOptions.get(api))
        try {
            Streams.drain(dIn)
            fail("Expected StreamOverflowException")
        } catch (ex: StreamOverflowException) {
            // expected
        }
    }
}
