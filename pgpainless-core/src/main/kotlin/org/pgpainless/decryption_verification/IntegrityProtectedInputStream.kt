// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPException
import org.pgpainless.exception.ModificationDetectionException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.io.InputStream

class IntegrityProtectedInputStream(
        private val inputStream: InputStream,
        private val encryptedData: PGPEncryptedData,
        private val options: ConsumerOptions
) : InputStream() {
    private var closed: Boolean = false

    override fun read() = inputStream.read()
    override fun read(b: ByteArray, off: Int, len: Int) = inputStream.read(b, off, len)
    override fun close() {
        if (closed) return

        closed = true
        if (encryptedData.isIntegrityProtected && !options.isIgnoreMDCErrors()) {
            try {
                if (!encryptedData.verify()) throw ModificationDetectionException()
                LOGGER.debug("Integrity Protection check passed.")
            } catch (e : PGPException) {
                throw IOException("Data appears to not be integrity protected.", e)
            }
        }
    }

    companion object {
        @JvmStatic
        val LOGGER: Logger = LoggerFactory.getLogger(IntegrityProtectedInputStream::class.java)
    }
}