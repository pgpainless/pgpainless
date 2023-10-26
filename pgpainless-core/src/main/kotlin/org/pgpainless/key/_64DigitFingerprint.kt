// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import java.nio.Buffer
import java.nio.ByteBuffer
import java.nio.charset.Charset
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.util.encoders.Hex

/**
 * This class represents a hex encoded, upper case OpenPGP v5 or v6 fingerprint. Since both
 * fingerprints use the same format, this class is used when parsing the fingerprint without knowing
 * the key version.
 */
open class _64DigitFingerprint : OpenPgpFingerprint {

    /**
     * Create an {@link _64DigitFingerprint}.
     *
     * @param fingerprint uppercase hexadecimal fingerprint of length 64
     */
    constructor(fingerprint: String) : super(fingerprint)

    constructor(bytes: ByteArray) : super(bytes)

    constructor(key: PGPPublicKey) : super(key)

    constructor(key: PGPSecretKey) : super(key)

    constructor(keys: PGPKeyRing) : super(keys)

    override val keyId: Long
        get() {
            val bytes = Hex.decode(fingerprint.toByteArray(Charset.forName("UTF-8")))
            val buf = ByteBuffer.wrap(bytes)

            // The key id is the left-most 8 bytes (conveniently a long).
            // We have to cast here in order to be compatible with java 8
            // https://github.com/eclipse/jetty.project/issues/3244
            (buf as Buffer).position(0)

            return buf.getLong()
        }

    override fun getVersion(): Int {
        return -1 // might be v5 or v6
    }

    override fun isValid(fingerprint: String): Boolean {
        return fingerprint.matches(("^[0-9A-F]{64}$".toRegex()))
    }

    override fun toString(): String {
        return super.toString()
    }

    override fun prettyPrint(): String {
        return buildString {
            for (i in 0 until 4) {
                append(fingerprint, i * 8, (i + 1) * 8).append(' ')
            }
            append(' ')
            for (i in 4 until 7) {
                append(fingerprint, i * 8, (i + 1) * 8).append(' ')
            }
            append(fingerprint, 56, 64)
        }
    }
}
