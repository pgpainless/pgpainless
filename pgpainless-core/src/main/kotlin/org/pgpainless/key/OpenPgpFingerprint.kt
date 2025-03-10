// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import java.nio.charset.Charset
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.util.encoders.Hex

/** Abstract super class of different version OpenPGP fingerprints. */
abstract class OpenPgpFingerprint : CharSequence, Comparable<OpenPgpFingerprint> {
    val fingerprint: String
    val bytes: ByteArray

    /**
     * Return the version of the fingerprint.
     *
     * @return version
     */
    abstract fun getVersion(): Int

    /**
     * Return the key id of the OpenPGP public key this [OpenPgpFingerprint] belongs to. This method
     * can be implemented for V4 and V5 fingerprints. V3 key-IDs cannot be derived from the
     * fingerprint, but we don't care, since V3 is deprecated.
     *
     * @return key id
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-12.2"> RFC-4880 §12.2: Key IDs and
     *   Fingerprints</a>
     */
    abstract val keyId: Long

    constructor(fingerprint: String) {
        val prep = fingerprint.replace(" ", "").trim().uppercase()
        if (!isValid(prep)) {
            throw IllegalArgumentException(
                "Fingerprint '$fingerprint' does not appear to be a valid OpenPGP V${getVersion()} fingerprint.")
        }
        this.fingerprint = prep
        this.bytes = Hex.decode(prep)
    }

    constructor(bytes: ByteArray) : this(Hex.toHexString(bytes))

    constructor(key: PGPPublicKey) : this(key.fingerprint) {
        if (key.version != getVersion()) {
            throw IllegalArgumentException("Key is not a v${getVersion()} OpenPgp key.")
        }
    }

    constructor(key: PGPSecretKey) : this(key.publicKey)

    constructor(keys: PGPKeyRing) : this(keys.publicKey)

    abstract val keyIdentifier: KeyIdentifier

    /**
     * Check, whether the fingerprint consists of 40 valid hexadecimal characters.
     *
     * @param fp fingerprint to check.
     * @return true if fingerprint is valid.
     */
    protected abstract fun isValid(fingerprint: String): Boolean

    override val length: Int
        get() = fingerprint.length

    override fun get(index: Int) = fingerprint.get(index)

    override fun subSequence(startIndex: Int, endIndex: Int) =
        fingerprint.subSequence(startIndex, endIndex)

    override fun compareTo(other: OpenPgpFingerprint): Int {
        return fingerprint.compareTo(other.fingerprint)
    }

    override fun equals(other: Any?): Boolean {
        return toString() == other.toString()
    }

    override fun hashCode(): Int {
        return toString().hashCode()
    }

    override fun toString(): String = fingerprint

    abstract fun prettyPrint(): String

    companion object {
        @JvmStatic val utf8: Charset = Charset.forName("UTF-8")

        /**
         * Return the fingerprint of the given key. This method automatically matches key versions
         * to fingerprint implementations.
         *
         * @param key key
         * @return fingerprint
         */
        @JvmStatic fun of(key: PGPSecretKey): OpenPgpFingerprint = of(key.publicKey)

        /**
         * Return the fingerprint of the given key. This method automatically matches key versions
         * to fingerprint implementations.
         *
         * @param key key
         * @return fingerprint
         */
        @JvmStatic
        fun of(key: PGPPublicKey): OpenPgpFingerprint =
            when (key.version) {
                4 -> OpenPgpV4Fingerprint(key)
                5 -> OpenPgpV5Fingerprint(key)
                6 -> OpenPgpV6Fingerprint(key)
                else ->
                    throw IllegalArgumentException(
                        "OpenPGP keys of version ${key.version} are not supported.")
            }

        /**
         * Return the fingerprint of the primary key of the given key ring. This method
         * automatically matches key versions to fingerprint implementations.
         *
         * @param ring key ring
         * @return fingerprint
         */
        @JvmStatic fun of(keys: PGPKeyRing): OpenPgpFingerprint = of(keys.publicKey)

        /** Return the [OpenPgpFingerprint] of the primary key of the given [OpenPGPCertificate]. */
        @JvmStatic fun of(cert: OpenPGPCertificate): OpenPgpFingerprint = of(cert.pgpPublicKeyRing)

        /** Return the [OpenPgpFingerprint] of the given [OpenPGPComponentKey]. */
        @JvmStatic fun of(key: OpenPGPComponentKey): OpenPgpFingerprint = of(key.pgpPublicKey)

        @JvmStatic fun of(key: OpenPGPPrivateKey): OpenPgpFingerprint = of(key.secretKey)

        /**
         * Try to parse an [OpenPgpFingerprint] from the given fingerprint string. If the trimmed
         * fingerprint without whitespace is 64 characters long, it is either a v5 or v6
         * fingerprint. In this case, we return a [_64DigitFingerprint]. Since this is ambiguous, it
         * is generally recommended to know the version of the key beforehand.
         *
         * @param fingerprint fingerprint
         * @return parsed fingerprint
         * @deprecated Use the constructor methods of the versioned fingerprint subclasses instead.
         */
        @JvmStatic
        @Deprecated("Use the constructor methods of the versioned fingerprint subclasses instead.")
        fun parse(fingerprint: String): OpenPgpFingerprint {
            val prep = fingerprint.replace(" ", "").trim().uppercase()
            if (prep.matches("^[0-9A-F]{40}$".toRegex())) {
                return OpenPgpV4Fingerprint(prep)
            }
            if (prep.matches("^[0-9A-F]{64}$".toRegex())) {
                // Might be v5 or v6 :/
                return _64DigitFingerprint(prep)
            }
            throw IllegalArgumentException(
                "Fingerprint does not appear to match any known fingerprint pattern.")
        }

        /**
         * Parse a binary OpenPGP fingerprint into an [OpenPgpFingerprint] object.
         *
         * @param binaryFingerprint binary representation of the fingerprint
         * @return parsed fingerprint
         * @deprecated use the parse() methods of the versioned fingerprint subclasses instead.
         */
        @JvmStatic
        @Deprecated("use the parse() methods of the versioned fingerprint subclasses instead.")
        fun parseFromBinary(binaryFingerprint: ByteArray): OpenPgpFingerprint =
            parse(Hex.toHexString(binaryFingerprint))
    }
}
