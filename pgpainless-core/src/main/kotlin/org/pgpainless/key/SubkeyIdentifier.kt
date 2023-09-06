// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey

/**
 * Tuple class used to identify a subkey by fingerprints of the primary key of the subkeys key ring,
 * as well as the subkeys fingerprint.
 */
class SubkeyIdentifier(
        val primaryKeyFingerprint: OpenPgpFingerprint,
        val subkeyFingerprint: OpenPgpFingerprint) {

    constructor(fingerprint: OpenPgpFingerprint): this(fingerprint, fingerprint)
    constructor(keys: PGPKeyRing): this(keys.publicKey)
    constructor(key: PGPPublicKey): this(OpenPgpFingerprint.of(key))
    constructor(keys: PGPKeyRing, keyId: Long): this(
                    OpenPgpFingerprint.of(keys.publicKey),
                    OpenPgpFingerprint.of(keys.getPublicKey(keyId) ?:
                    throw NoSuchElementException("OpenPGP key does not contain subkey ${keyId.openPgpKeyId()}")))
    constructor(keys: PGPKeyRing, subkeyFingerprint: OpenPgpFingerprint): this(OpenPgpFingerprint.of(keys), subkeyFingerprint)

    val keyId = subkeyFingerprint.keyId
    val fingerprint = subkeyFingerprint

    val subkeyId = subkeyFingerprint.keyId
    val primaryKeyId = primaryKeyFingerprint.keyId

    override fun equals(other: Any?): Boolean {
        if (other == null) {
            return false
        }
        if (this === other) {
            return true
        }
        if (other !is SubkeyIdentifier) {
            return false
        }

        return primaryKeyFingerprint == other.primaryKeyFingerprint && subkeyFingerprint == other.subkeyFingerprint
    }

    override fun hashCode(): Int {
        return primaryKeyFingerprint.hashCode() + 31 * subkeyFingerprint.hashCode()
    }

    override fun toString(): String = "$subkeyFingerprint $primaryKeyFingerprint"
}