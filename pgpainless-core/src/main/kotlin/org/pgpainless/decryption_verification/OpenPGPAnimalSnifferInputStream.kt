// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.InputStream
import org.bouncycastle.bcpg.AEADEncDataPacket
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.CompressedDataPacket
import org.bouncycastle.bcpg.LiteralDataPacket
import org.bouncycastle.bcpg.MarkerPacket
import org.bouncycastle.bcpg.OnePassSignaturePacket
import org.bouncycastle.bcpg.PacketFormat
import org.bouncycastle.bcpg.PacketTags.AEAD_ENC_DATA
import org.bouncycastle.bcpg.PacketTags.COMPRESSED_DATA
import org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_1
import org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_2
import org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_3
import org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_4
import org.bouncycastle.bcpg.PacketTags.LITERAL_DATA
import org.bouncycastle.bcpg.PacketTags.MARKER
import org.bouncycastle.bcpg.PacketTags.MOD_DETECTION_CODE
import org.bouncycastle.bcpg.PacketTags.ONE_PASS_SIGNATURE
import org.bouncycastle.bcpg.PacketTags.PADDING
import org.bouncycastle.bcpg.PacketTags.PUBLIC_KEY
import org.bouncycastle.bcpg.PacketTags.PUBLIC_KEY_ENC_SESSION
import org.bouncycastle.bcpg.PacketTags.PUBLIC_SUBKEY
import org.bouncycastle.bcpg.PacketTags.RESERVED
import org.bouncycastle.bcpg.PacketTags.SECRET_KEY
import org.bouncycastle.bcpg.PacketTags.SECRET_SUBKEY
import org.bouncycastle.bcpg.PacketTags.SIGNATURE
import org.bouncycastle.bcpg.PacketTags.SYMMETRIC_KEY_ENC
import org.bouncycastle.bcpg.PacketTags.SYMMETRIC_KEY_ENC_SESSION
import org.bouncycastle.bcpg.PacketTags.SYM_ENC_INTEGRITY_PRO
import org.bouncycastle.bcpg.PacketTags.TRUST
import org.bouncycastle.bcpg.PacketTags.USER_ATTRIBUTE
import org.bouncycastle.bcpg.PacketTags.USER_ID
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.bcpg.SignaturePacket
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket
import org.bouncycastle.util.Arrays
import org.pgpainless.algorithm.AEADAlgorithm
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

/**
 * InputStream used to determine the nature of potential OpenPGP data.
 *
 * @param input underlying input stream
 * @param check whether to perform the costly checking inside the constructor
 */
class OpenPGPAnimalSnifferInputStream(input: InputStream, check: Boolean) :
    BufferedInputStream(input) {

    private val buffer: ByteArray
    private val bufferLen: Int

    private var containsArmorHeader: Boolean = false
    private var containsOpenPgpPackets: Boolean = false
    private var resemblesMessage: Boolean = false

    init {
        mark(MAX_BUFFER_SIZE)
        buffer = ByteArray(MAX_BUFFER_SIZE)
        bufferLen = read(buffer)
        reset()

        if (check) {
            inspectBuffer()
        }
    }

    constructor(input: InputStream) : this(input, true)

    /** Return true, if the underlying data is ASCII armored. */
    val isAsciiArmored: Boolean
        get() = containsArmorHeader

    /**
     * Return true, if the data is possibly binary OpenPGP. The criterion for this are less strict
     * than for [resemblesMessage], as it also accepts other OpenPGP packets at the beginning of the
     * data stream.
     *
     * <p>
     * Use with caution.
     *
     * @return true if data appears to be binary OpenPGP data
     */
    val isBinaryOpenPgp: Boolean
        get() = containsOpenPgpPackets

    /**
     * Returns true, if the underlying data is very likely (more than 99,9%) an OpenPGP message.
     * OpenPGP Message means here that it starts with either a [PGPEncryptedData],
     * [PGPCompressedData], [PGPOnePassSignature] or [PGPLiteralData] packet. The plausibility of
     * these data packets is checked as far as possible.
     *
     * @return true if likely OpenPGP message
     */
    val isLikelyOpenPgpMessage: Boolean
        get() = resemblesMessage

    /** Return true, if the underlying data is non-OpenPGP data. */
    val isNonOpenPgp: Boolean
        get() = !isAsciiArmored && !isBinaryOpenPgp

    /** Costly perform a plausibility check of the first encountered OpenPGP packet. */
    fun inspectBuffer() {
        if (checkForAsciiArmor()) {
            return
        }

        checkForBinaryOpenPgp()
    }

    private fun checkForAsciiArmor(): Boolean {
        if (startsWithIgnoringWhitespace(buffer, ARMOR_HEADER, bufferLen)) {
            containsArmorHeader = true
            return true
        }
        return false
    }

    /**
     * This method is still brittle. Basically we try to parse OpenPGP packets from the buffer. If
     * we run into exceptions, then we know that the data is non-OpenPGP'ish.
     *
     * <p>
     * This breaks down though if we read plausible garbage where the data accidentally makes sense,
     * or valid, yet incomplete packets (remember, we are still only working on a portion of the
     * data).
     */
    private fun checkForBinaryOpenPgp() {
        if (bufferLen == -1) {
            // empty data
            return
        }

        val bufferIn = ByteArrayInputStream(buffer, 0, bufferLen)
        val pIn = BCPGInputStream(bufferIn)
        try {
            nonExhaustiveParseAndCheckPlausibility(pIn)
        } catch (e: Exception) {
            return
        }
    }

    private fun nonExhaustiveParseAndCheckPlausibility(packetIn: BCPGInputStream) {
        val packet = packetIn.readPacket()
        when (packet.packetTag) {
            PUBLIC_KEY_ENC_SESSION -> {
                packet as PublicKeyEncSessionPacket
                if (PublicKeyAlgorithm.fromId(packet.algorithm) == null) {
                    return
                }
            }
            SIGNATURE -> {
                packet as SignaturePacket
                if (SignatureType.fromCode(packet.signatureType) == null) {
                    return
                }
                if (PublicKeyAlgorithm.fromId(packet.keyAlgorithm) == null) {
                    return
                }
                if (HashAlgorithm.fromId(packet.hashAlgorithm) == null) {
                    return
                }
            }
            ONE_PASS_SIGNATURE -> {
                packet as OnePassSignaturePacket
                if (SignatureType.fromCode(packet.signatureType) == null) {
                    return
                }
                if (PublicKeyAlgorithm.fromId(packet.keyAlgorithm) == null) {
                    return
                }
                if (HashAlgorithm.fromId(packet.hashAlgorithm) == null) {
                    return
                }
            }
            SYMMETRIC_KEY_ENC_SESSION -> {
                packet as SymmetricKeyEncSessionPacket
                if (SymmetricKeyAlgorithm.fromId(packet.encAlgorithm) == null) {
                    return
                }
            }
            SECRET_KEY -> {
                packet as SecretKeyPacket
                val publicKey = packet.publicKeyPacket
                if (PublicKeyAlgorithm.fromId(publicKey.algorithm) == null) {
                    return
                }
                if (publicKey.version !in 3..6) {
                    return
                }
            }
            PUBLIC_KEY -> {
                packet as PublicKeyPacket
                if (PublicKeyAlgorithm.fromId(packet.algorithm) == null) {
                    return
                }
                if (packet.version !in 3..6) {
                    return
                }
            }
            COMPRESSED_DATA -> {
                packet as CompressedDataPacket
                if (CompressionAlgorithm.fromId(packet.algorithm) == null) {
                    return
                }
            }
            SYMMETRIC_KEY_ENC -> {
                // Not much we can check here
            }
            MARKER -> {
                packet as MarkerPacket
                if (!Arrays.areEqual(
                    packet.getEncoded(PacketFormat.CURRENT),
                    byteArrayOf(0xca.toByte(), 0x03, 0x50, 0x47, 0x50),
                )) {
                    return
                }
            }
            LITERAL_DATA -> {
                packet as LiteralDataPacket
                if (packet.format.toChar() !in charArrayOf('b', 'u', 't', 'l', '1', 'm')) {
                    return
                }
            }
            SYM_ENC_INTEGRITY_PRO -> {
                packet as SymmetricEncIntegrityPacket
                if (packet.version !in
                    intArrayOf(
                        SymmetricEncIntegrityPacket.VERSION_1,
                        SymmetricEncIntegrityPacket.VERSION_2)) {
                    return
                }

                if (packet.version == SymmetricEncIntegrityPacket.VERSION_2) {
                    if (SymmetricKeyAlgorithm.fromId(packet.cipherAlgorithm) == null) {
                        return
                    }
                    if (AEADAlgorithm.fromId(packet.aeadAlgorithm) == null) {
                        return
                    }
                }
            }
            AEAD_ENC_DATA -> {
                packet as AEADEncDataPacket
                if (SymmetricKeyAlgorithm.fromId(packet.algorithm.toInt()) == null) {
                    return
                }
            }
            RESERVED, // this Packet Type ID MUST NOT be used
            PUBLIC_SUBKEY, // Never found at the start of a stream
            SECRET_SUBKEY, // Never found at the start of a stream
            TRUST, // Never found at the start of a stream
            MOD_DETECTION_CODE, // At the end of SED data - Never found at the start of a stream
            USER_ID, // Never found at the start of a stream
            USER_ATTRIBUTE, // Never found at the start of a stream
            PADDING, // At the end of messages (optionally padded message) or certificates
            EXPERIMENTAL_1, // experimental
            EXPERIMENTAL_2, // experimental
            EXPERIMENTAL_3, // experimental
            EXPERIMENTAL_4 -> { // experimental
                containsOpenPgpPackets = true
                resemblesMessage = false
                return
            }
            else -> return
        }

        containsOpenPgpPackets = true
        if (packet.packetTag != SYMMETRIC_KEY_ENC) {
            resemblesMessage = true
        }
    }

    private fun startsWithIgnoringWhitespace(
        bytes: ByteArray,
        subSequence: CharSequence,
        bufferLen: Int
    ): Boolean {
        if (bufferLen == -1) {
            return false
        }

        for (i in 0 until bufferLen) {
            // Working on bytes is not trivial with unicode data, but its good enough here
            if (Character.isWhitespace(bytes[i].toInt())) {
                continue
            }

            if ((i + subSequence.length) > bytes.size) {
                return false
            }

            for (j in subSequence.indices) {
                if (bytes[i + j].toInt().toChar() != subSequence[j]) {
                    return false
                }
            }
            return true
        }
        return false
    }

    companion object {
        const val ARMOR_HEADER = "-----BEGIN PGP "
        const val MAX_BUFFER_SIZE = 8192 * 2
    }
}
