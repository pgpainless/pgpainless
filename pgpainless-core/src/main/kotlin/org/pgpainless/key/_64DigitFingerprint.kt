// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.bouncycastle.bcpg.FingerprintUtil
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey

/**
 * This class represents a hex encoded, upper case OpenPGP v5 or v6 fingerprint. Since both
 * fingerprints use the same format, this class is used when parsing the fingerprint without knowing
 * the key version.
 */
open class _64DigitFingerprint : OpenPgpFingerprint {

    /**
     * Create a [_64DigitFingerprint].
     *
     * @param fingerprint uppercase hexadecimal fingerprint of length 64
     */
    constructor(fingerprint: String) : super(fingerprint)

    constructor(bytes: ByteArray) : super(bytes)

    constructor(key: PGPPublicKey) : super(key)

    constructor(key: PGPSecretKey) : super(key)

    constructor(keys: PGPKeyRing) : super(keys)

    override val keyId: Long = FingerprintUtil.keyIdFromV6Fingerprint(bytes)

    override fun getVersion(): Int {
        return -1 // might be v5 or v6
    }

    override val keyIdentifier: KeyIdentifier = KeyIdentifier(bytes)

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
