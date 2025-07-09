// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.MarkerPacket
import org.bouncycastle.bcpg.Packet
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPPadding
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.OpenPgpPacket
import org.pgpainless.exception.MalformedOpenPgpMessageException

/**
 * Since we need to update signatures with data from the underlying stream, this class is used to
 * tee out the data. Unfortunately we cannot simply override [BCPGInputStream.read] to tee the data
 * out though, since [BCPGInputStream.readPacket] inconsistently calls a mix of
 * [BCPGInputStream.read] and [InputStream.read] of the underlying stream. This would cause the
 * second length byte to get swallowed up.
 *
 * Therefore, this class delegates the teeing to an [DelayedTeeInputStream] which wraps the
 * underlying stream. Since calling [BCPGInputStream.nextPacketTag] reads up to and including the
 * next packets tag, we need to delay teeing out that byte to signature verifiers. Hence, the
 * reading methods of the [TeeBCPGInputStream] handle pushing this byte to the output stream using
 * [DelayedTeeInputStream.squeeze].
 */
class TeeBCPGInputStream(inputStream: BCPGInputStream, outputStream: OutputStream) {

    private val delayedTee: DelayedTeeInputStream
    private val packetInputStream: BCPGInputStream

    init {
        delayedTee = DelayedTeeInputStream(inputStream, outputStream)
        packetInputStream = BCPGInputStream(delayedTee)
    }

    fun nextPacketTag(): OpenPgpPacket? {
        return packetInputStream.nextPacketTag().let {
            if (it == -1) null else OpenPgpPacket.requireFromTag(it)
        }
    }

    fun readPacket(): Packet = packetInputStream.readPacket()

    fun readCompressedData(): PGPCompressedData {
        delayedTee.squeeze()
        return PGPCompressedData(packetInputStream)
    }

    fun readLiteralData(): PGPLiteralData {
        delayedTee.squeeze()
        return PGPLiteralData(packetInputStream)
    }

    fun readEncryptedDataList(): PGPEncryptedDataList {
        delayedTee.squeeze()
        return try {
            PGPEncryptedDataList(packetInputStream)
        } catch (e: IllegalArgumentException) {
            // Mismatched SKESK / SEIPD version
            throw MalformedOpenPgpMessageException(e)
        }
    }

    fun readOnePassSignature(): PGPOnePassSignature {
        return PGPOnePassSignature(packetInputStream).also { delayedTee.squeeze() }
    }

    fun readSignature(): PGPSignature {
        return PGPSignature(packetInputStream).also { delayedTee.squeeze() }
    }

    fun readMarker(): MarkerPacket {
        return (readPacket() as MarkerPacket).also { delayedTee.squeeze() }
    }

    fun readPadding(): PGPPadding {
        return PGPPadding(packetInputStream).also { delayedTee.squeeze() }
    }

    fun close() {
        packetInputStream.close()
    }

    class DelayedTeeInputStream(
        private val inputStream: InputStream,
        private val outputStream: OutputStream
    ) : InputStream() {
        private var last: Int = -1

        override fun read(): Int {
            if (last != -1) {
                outputStream.write(last)
            }
            return try {
                last = inputStream.read()
                last
            } catch (e: IOException) {
                if (e.message?.contains("crc check failed in armored message") == true) {
                    throw e
                }
                -1
            }
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (last != -1) {
                outputStream.write(last)
            }

            inputStream.read(b, off, len).let { r ->
                last =
                    if (r > 0) {
                        outputStream.write(b, off, r - 1)
                        b[off + r - 1].toInt()
                    } else {
                        -1
                    }
                return r
            }
        }

        /** Squeeze the last byte out and update the output stream. */
        fun squeeze() {
            if (last != -1) {
                outputStream.write(last)
            }
            last = -1
        }

        override fun close() {
            inputStream.close()
            outputStream.close()
        }
    }
}
