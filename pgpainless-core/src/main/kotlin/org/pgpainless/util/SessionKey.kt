// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.util.encoders.Hex
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

/**
 * A [SessionKey] is the symmetric key that is used to encrypt/decrypt an OpenPGP message payload.
 * The OpenPGP message header contains a copy of the session key, encrypted for the public key of
 * each recipient.
 *
 * @param algorithm symmetric key algorithm
 * @param key bytes of the key
 */
data class SessionKey(val algorithm: SymmetricKeyAlgorithm, val key: ByteArray) {

    /**
     * Constructor to create a session key from a BC [PGPSessionKey] object.
     *
     * @param sessionKey BC session key
     */
    constructor(
        sessionKey: PGPSessionKey
    ) : this(SymmetricKeyAlgorithm.requireFromId(sessionKey.algorithm), sessionKey.key)

    override fun toString(): String {
        return "${algorithm.algorithmId}:${Hex.toHexString(key)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SessionKey

        if (algorithm != other.algorithm) return false
        if (!key.contentEquals(other.key)) return false

        return true
    }

    override fun hashCode(): Int {
        return 31 * algorithm.hashCode() + key.contentHashCode()
    }
}
