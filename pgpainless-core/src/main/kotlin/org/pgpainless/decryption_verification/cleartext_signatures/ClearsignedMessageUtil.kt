// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures

import java.io.*
import kotlin.jvm.Throws
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.util.Strings
import org.pgpainless.exception.WrongConsumingMethodException
import org.pgpainless.util.ArmoredInputStreamFactory

/**
 * Utility class to deal with cleartext-signed messages. Based on Bouncycastle's
 * [org.bouncycastle.openpgp.examples.ClearSignedFileProcessor].
 */
class ClearsignedMessageUtil {

    companion object {

        /**
         * Dearmor a clearsigned message, detach the inband signatures and write the plaintext
         * message to the provided messageOutputStream.
         *
         * @param clearsignedInputStream input stream containing a clearsigned message
         * @param messageOutputStream output stream to which the dearmored message shall be written
         * @return signatures
         * @throws IOException if the message is not clearsigned or some other IO error happens
         * @throws WrongConsumingMethodException in case the armored message is not cleartext signed
         */
        @JvmStatic
        @Throws(WrongConsumingMethodException::class, IOException::class)
        fun detachSignaturesFromInbandClearsignedMessage(
            clearsignedInputStream: InputStream,
            messageOutputStream: OutputStream
        ): PGPSignatureList {
            val input: ArmoredInputStream =
                if (clearsignedInputStream is ArmoredInputStream) {
                    clearsignedInputStream
                } else {
                    ArmoredInputStreamFactory.get(clearsignedInputStream)
                }

            if (!input.isClearText) {
                throw WrongConsumingMethodException(
                    "Message isn't using the Cleartext Signature Framework.")
            }

            BufferedOutputStream(messageOutputStream).use { output ->
                val lineOut = ByteArrayOutputStream()
                var lookAhead = readInputLine(lineOut, input)
                val lineSep = getLineSeparator()

                if (lookAhead != -1 && input.isClearText) {
                    var line = lineOut.toByteArray()
                    output.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line))

                    while (lookAhead != -1 && input.isClearText) {
                        lookAhead = readInputLine(lineOut, lookAhead, input)
                        line = lineOut.toByteArray()
                        output.write(lineSep)
                        output.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line))
                    }
                } else {
                    if (lookAhead != -1) {
                        val line = lineOut.toByteArray()
                        output.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line))
                    }
                }
            }

            val objectFactory = OpenPGPImplementation.getInstance().pgpObjectFactory(input)
            val next = objectFactory.nextObject() ?: PGPSignatureList(arrayOf())
            return next as PGPSignatureList
        }

        @JvmStatic
        private fun readInputLine(bOut: ByteArrayOutputStream, fIn: InputStream): Int {
            bOut.reset()

            var lookAhead = -1
            var ch: Int

            while (fIn.read().also { ch = it } >= 0) {
                bOut.write(ch)
                if (ch == '\r'.code || ch == '\n'.code) {
                    lookAhead = readPassedEOL(bOut, ch, fIn)
                    break
                }
            }

            return lookAhead
        }

        @JvmStatic
        private fun readInputLine(
            bOut: ByteArrayOutputStream,
            lookAhead: Int,
            fIn: InputStream
        ): Int {
            var mLookAhead = lookAhead
            bOut.reset()
            var ch = mLookAhead
            do {
                bOut.write(ch)
                if (ch == '\r'.code || ch == '\n'.code) {
                    mLookAhead = readPassedEOL(bOut, ch, fIn)
                    break
                }
            } while (fIn.read().also { ch = it } >= 0)
            if (ch < 0) {
                mLookAhead = -1
            }
            return mLookAhead
        }

        @JvmStatic
        private fun readPassedEOL(bOut: ByteArrayOutputStream, lastCh: Int, fIn: InputStream): Int {
            var lookAhead = fIn.read()
            if (lastCh == '\r'.code && lookAhead == '\n'.code) {
                bOut.write(lookAhead)
                lookAhead = fIn.read()
            }
            return lookAhead
        }

        @JvmStatic
        private fun getLineSeparator(): ByteArray {
            val nl = Strings.lineSeparator()
            val nlBytes = ByteArray(nl.length)
            for (i in nlBytes.indices) {
                nlBytes[i] = nl[i].code.toByte()
            }
            return nlBytes
        }

        @JvmStatic
        private fun getLengthWithoutSeparatorOrTrailingWhitespace(line: ByteArray): Int {
            var end = line.size - 1
            while (end >= 0 && isWhiteSpace(line[end])) {
                end--
            }
            return end + 1
        }

        @JvmStatic
        private fun isLineEnding(b: Byte): Boolean {
            return b == '\r'.code.toByte() || b == '\n'.code.toByte()
        }

        @JvmStatic
        private fun isWhiteSpace(b: Byte): Boolean {
            return isLineEnding(b) || b == '\t'.code.toByte() || b == ' '.code.toByte()
        }
    }
}
