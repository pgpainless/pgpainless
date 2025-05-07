// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.util.io.Streams
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.decryption_verification.OpenPgpInputStream
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.util.KeyRingUtils

class ArmorUtils {

    companion object {
        // MessageIDs are 32 printable characters
        private val PATTER_MESSAGE_ID = "^\\S{32}$".toRegex()
        /** Constant armor key for comments. */
        const val HEADER_COMMENT = "Comment"
        /** Constant armor key for program versions. */
        const val HEADER_VERSION = "Version"
        /** Constant armor key for message IDs. Useful for split messages. */
        const val HEADER_MESSAGEID = "MessageID"
        /** Constant armor key for used hash algorithms in clearsigned messages. */
        const val HEADER_HASH = "Hash"
        /** Constant armor key for message character sets. */
        const val HEADER_CHARSET = "Charset"

        /**
         * Return the ASCII armored encoding of the given [PGPSecretKey].
         *
         * @param secretKey secret key
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredString(secretKey: PGPSecretKey): String =
            toAsciiArmoredString(secretKey.encoded, keyToHeader(secretKey.publicKey))

        /**
         * Return the ASCII armored encoding of the given [PGPPublicKey].
         *
         * @param publicKey public key
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredString(publicKey: PGPPublicKey): String =
            toAsciiArmoredString(publicKey.encoded, keyToHeader(publicKey))

        /**
         * Return the ASCII armored encoding of the given [PGPSecretKeyRing].
         *
         * @param secretKeys secret key ring
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredString(secretKeys: PGPSecretKeyRing): String =
            toAsciiArmoredString(secretKeys.encoded, keyToHeader(secretKeys.publicKey))

        /**
         * Return the ASCII armored encoding of the given [PGPPublicKeyRing].
         *
         * @param certificate public key ring
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredString(certificate: PGPPublicKeyRing): String =
            toAsciiArmoredString(certificate.encoded, keyToHeader(certificate.publicKey))

        /**
         * Return the ASCII armored encoding of the given [PGPSecretKeyRingCollection]. The encoding
         * will use per-key ASCII armors protecting each [PGPSecretKeyRing] individually. Those
         * armors are then concatenated with newlines in between.
         *
         * @param secretKeysCollection secret key ring collection
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredString(secretKeysCollection: PGPSecretKeyRingCollection): String =
            secretKeysCollection.keyRings.asSequence().joinToString("\n") {
                toAsciiArmoredString(it)
            }

        /**
         * Return the ASCII armored encoding of the given [PGPPublicKeyRingCollection]. The encoding
         * will use per-key ASCII armors protecting each [PGPPublicKeyRing] individually. Those
         * armors are then concatenated with newlines in between.
         *
         * @param certificates public key ring collection
         * @return ascii armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredString(certificates: PGPPublicKeyRingCollection): String =
            certificates.joinToString("\n") { toAsciiArmoredString(it) }

        /**
         * Return the ASCII armored representation of the given detached signature. If [export] is
         * true, the signature will be stripped of non-exportable subpackets or trust-packets. If it
         * is false, the signature will be encoded as-is.
         *
         * @param signature signature
         * @param export whether to exclude non-exportable subpackets or trust-packets.
         * @return ascii armored string
         * @throws IOException in case of an error in the [ArmoredOutputStream]
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun toAsciiArmoredString(signature: PGPSignature, export: Boolean = false): String =
            toAsciiArmoredString(signature.getEncoded(export))

        /**
         * Return the ASCII armored encoding of the given OpenPGP data bytes. The ASCII armor will
         * include headers from the header map.
         *
         * @param bytes OpenPGP data
         * @param header header map
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun toAsciiArmoredString(
            bytes: ByteArray,
            header: Map<String, Set<String>>? = null
        ): String = toAsciiArmoredString(bytes.inputStream(), header)

        /**
         * Return the ASCII armored encoding of the OpenPGP data from the given [InputStream]. The
         * ASCII armor will include armor headers from the given header map.
         *
         * @param inputStream input stream of OpenPGP data
         * @param header ASCII armor header map
         * @return ASCII armored encoding
         * @throws IOException in case of an io error
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun toAsciiArmoredString(
            inputStream: InputStream,
            header: Map<String, Set<String>>? = null
        ): String =
            ByteArrayOutputStream()
                .apply {
                    toAsciiArmoredStream(this, header).run {
                        Streams.pipeAll(inputStream, this)
                        this.close()
                    }
                }
                .toString()

        /**
         * Return an [ArmoredOutputStream] prepared with headers for the given key ring, which wraps
         * the given [OutputStream].
         *
         * The armored output stream can be used to encode the key ring by calling
         * [PGPKeyRing.encode] with the armored output stream as an argument.
         *
         * @param keys OpenPGP key or certificate
         * @param outputStream wrapped output stream
         * @return armored output stream
         */
        @JvmStatic
        @Throws(IOException::class)
        fun toAsciiArmoredStream(
            keys: PGPKeyRing,
            outputStream: OutputStream
        ): ArmoredOutputStream = toAsciiArmoredStream(outputStream, keyToHeader(keys.publicKey))

        /**
         * Create an [ArmoredOutputStream] wrapping the given [OutputStream]. The armored output
         * stream will be prepared with armor headers given by header.
         *
         * Note: Since the armored output stream is retrieved from [ArmoredOutputStreamFactory.get],
         * it may already come with custom headers. Hence, the header entries given by header are
         * appended below those already populated headers.
         *
         * @param outputStream output stream to wrap
         * @param header map of header entries
         * @return armored output stream
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun toAsciiArmoredStream(
            outputStream: OutputStream,
            header: Map<String, Set<String>>? = null
        ): ArmoredOutputStream =
            ArmoredOutputStreamFactory.get(outputStream).apply {
                header?.forEach { entry ->
                    entry.value.forEach { value -> addHeader(entry.key, value) }
                }
            }

        /**
         * Generate a header map for ASCII armor from the given [PGPPublicKey]. The header map
         * consists of a comment field of the keys pretty-printed fingerprint, as well as the
         * primary or first user-id plus the count of remaining user-ids.
         *
         * @param publicKey public key
         * @return header map
         */
        @JvmStatic
        fun keyToHeader(publicKey: PGPPublicKey): Map<String, Set<String>> {
            val headerMap = mutableMapOf<String, MutableSet<String>>()
            val userIds = KeyRingUtils.getUserIdsIgnoringInvalidUTF8(publicKey)
            val first: String? = userIds.firstOrNull()
            val primary: String? =
                userIds.firstOrNull {
                    publicKey.getSignaturesForID(it)?.asSequence()?.any { sig ->
                        sig.hashedSubPackets.isPrimaryUserID
                    }
                        ?: false
                }

            // Fingerprint
            headerMap
                .getOrPut(HEADER_COMMENT) { mutableSetOf() }
                .add(OpenPgpFingerprint.of(publicKey).prettyPrint())
            // Primary / First User ID
            (primary ?: first)?.let {
                headerMap.getOrPut(HEADER_COMMENT) { mutableSetOf() }
                    .add(it.replace("\n", "\\n").replace("\r", "\\r"))
            }
            // X-1 further identities
            when (userIds.size) {
                0,
                1 -> {}
                2 -> headerMap.getOrPut(HEADER_COMMENT) { mutableSetOf() }.add("1 further identity")
                else ->
                    headerMap
                        .getOrPut(HEADER_COMMENT) { mutableSetOf() }
                        .add("${userIds.size - 1} further identities")
            }
            return headerMap
        }

        /**
         * Set the version header entry in the ASCII armor. If the version info is null or only
         * contains whitespace characters, then the version header will be removed.
         *
         * @param armor armored output stream
         * @param version version header.
         */
        @JvmStatic
        @Deprecated(
            "Changing ASCII armor headers after ArmoredOutputStream creation is deprecated. " +
                "Use ArmoredOutputStream builder instead.")
        fun setVersionHeader(armor: ArmoredOutputStream, version: String?) =
            armor.setHeader(HEADER_VERSION, version?.let { it.ifBlank { null } })

        /**
         * Add an ASCII armor header entry about the used hash algorithm into the
         * [ArmoredOutputStream].
         *
         * @param armor armored output stream
         * @param hashAlgorithm hash algorithm
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.2"> RFC 4880 -
         *   OpenPGP Message Format §6.2. Forming ASCII Armor</a>
         */
        @JvmStatic
        @Deprecated(
            "Changing ASCII armor headers after ArmoredOutputStream creation is deprecated. " +
                "Use ArmoredOutputStream builder instead.")
        fun addHashAlgorithmHeader(armor: ArmoredOutputStream, hashAlgorithm: HashAlgorithm) =
            armor.addHeader(HEADER_HASH, hashAlgorithm.algorithmName)

        /**
         * Add an ASCII armor comment header entry into the [ArmoredOutputStream].
         *
         * @param armor armored output stream
         * @param comment free-text comment
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.2"> RFC 4880 -
         *   OpenPGP Message Format §6.2. Forming ASCII Armor</a>
         */
        @JvmStatic
        @Deprecated(
            "Changing ASCII armor headers after ArmoredOutputStream creation is deprecated. " +
                "Use ArmoredOutputStream builder instead.")
        fun addCommentHeader(armor: ArmoredOutputStream, comment: String) =
            armor.addHeader(HEADER_COMMENT, comment)

        /**
         * Add an ASCII armor message-id header entry into the [ArmoredOutputStream].
         *
         * @param armor armored output stream
         * @param messageId message id
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.2"> RFC 4880 -
         *   OpenPGP Message Format §6.2. Forming ASCII Armor</a>
         */
        @JvmStatic
        @Deprecated(
            "Changing ASCII armor headers after ArmoredOutputStream creation is deprecated. " +
                "Use ArmoredOutputStream builder instead.")
        fun addMessageIdHeader(armor: ArmoredOutputStream, messageId: String) {
            require(PATTER_MESSAGE_ID.matches(messageId)) {
                "MessageIDs MUST consist of 32 printable characters."
            }
            armor.addHeader(HEADER_MESSAGEID, messageId)
        }

        /**
         * Extract all ASCII armor header values of type comment from the given
         * [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @return list of comment headers
         */
        @JvmStatic
        fun getCommentHeaderValues(armor: ArmoredInputStream): List<String> =
            getArmorHeaderValues(armor, HEADER_COMMENT)

        /**
         * Extract all ASCII armor header values of type message id from the given
         * [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @return list of message-id headers
         */
        @JvmStatic
        fun getMessageIdHeaderValues(armor: ArmoredInputStream): List<String> =
            getArmorHeaderValues(armor, HEADER_MESSAGEID)

        /**
         * Return all ASCII armor header values of type hash-algorithm from the given
         * [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @return list of hash headers
         */
        @JvmStatic
        fun getHashHeaderValues(armor: ArmoredInputStream): List<String> =
            getArmorHeaderValues(armor, HEADER_HASH)

        /**
         * Return a list of [HashAlgorithm] enums extracted from the hash header entries of the
         * given [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @return list of hash algorithms from the ASCII header
         */
        @JvmStatic
        fun getHashAlgorithms(armor: ArmoredInputStream): List<HashAlgorithm> =
            getHashHeaderValues(armor).mapNotNull { HashAlgorithm.fromName(it) }

        /**
         * Return all ASCII armor header values of type version from the given [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @return list of version headers
         */
        @JvmStatic
        fun getVersionHeaderValues(armor: ArmoredInputStream): List<String> =
            getArmorHeaderValues(armor, HEADER_VERSION)

        /**
         * Return all ASCII armor header values of type charset from the given [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @return list of charset headers
         */
        @JvmStatic
        fun getCharsetHeaderValues(armor: ArmoredInputStream): List<String> =
            getArmorHeaderValues(armor, HEADER_CHARSET)

        /**
         * Return all ASCII armor header values of the given headerKey from the given
         * [ArmoredInputStream].
         *
         * @param armor armored input stream
         * @param key ASCII armor header key
         * @return list of values for the header key
         */
        @JvmStatic
        fun getArmorHeaderValues(armor: ArmoredInputStream, key: String): List<String> =
            armor.armorHeaders
                .filter { it.startsWith("$key: ") }
                .map { it.substring(key.length + 2) } // key.len + ": ".len

        /**
         * Hacky workaround for #96. For `PGPPublicKeyRingCollection(InputStream,
         * KeyFingerPrintCalculator)` or `PGPSecretKeyRingCollection(InputStream,
         * KeyFingerPrintCalculator)` to read all PGPKeyRings properly, we apparently have to make
         * sure that the [InputStream] that is given as constructor argument is a
         * [PGPUtil.BufferedInputStreamExt]. Since [PGPUtil.getDecoderStream] will return an
         * [org.bouncycastle.bcpg.ArmoredInputStream] if the underlying input stream contains
         * armored data, we first dearmor the data ourselves to make sure that the end-result is a
         * [PGPUtil.BufferedInputStreamExt].
         *
         * @param inputStream input stream
         * @return BufferedInputStreamExt
         * @throws IOException in case of an IO error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun getDecoderStream(inputStream: InputStream): InputStream =
            OpenPgpInputStream(inputStream).let {
                if (it.isAsciiArmored) {
                    PGPUtil.getDecoderStream(ArmoredInputStreamFactory.get(it))
                } else {
                    it
                }
            }
    }
}
