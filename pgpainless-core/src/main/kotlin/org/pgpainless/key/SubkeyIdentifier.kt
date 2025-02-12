// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey

/**
 * Tuple class used to identify a subkey by fingerprints of the primary key of the subkeys key ring,
 * as well as the subkeys fingerprint.
 */
class SubkeyIdentifier(
    val primaryKeyFingerprint: OpenPgpFingerprint,
    val subkeyFingerprint: OpenPgpFingerprint
) {

    constructor(fingerprint: OpenPgpFingerprint) : this(fingerprint, fingerprint)

    constructor(keys: PGPKeyRing) : this(keys.publicKey)

    constructor(key: PGPPublicKey) : this(OpenPgpFingerprint.of(key))

    constructor(keys: PGPKeyRing, keyId: Long) : this(keys, KeyIdentifier(keyId))

    constructor(
        key: OpenPGPComponentKey
    ) : this(
        OpenPgpFingerprint.of(key.certificate.pgpPublicKeyRing),
        OpenPgpFingerprint.of(key.pgpPublicKey))

    constructor(key: OpenPGPPrivateKey) : this(key.secretKey)

    constructor(
        keys: PGPKeyRing,
        subkeyFingerprint: OpenPgpFingerprint
    ) : this(OpenPgpFingerprint.of(keys), subkeyFingerprint)

    constructor(
        keys: PGPKeyRing,
        subkeyIdentifier: KeyIdentifier
    ) : this(
        OpenPgpFingerprint.of(keys),
        OpenPgpFingerprint.of(
            keys.getPublicKey(subkeyIdentifier)
                ?: throw NoSuchElementException(
                    "OpenPGP key does not contain subkey $subkeyIdentifier")))

    val keyIdentifier = KeyIdentifier(subkeyFingerprint.bytes)
    val subkeyIdentifier = keyIdentifier
    val primaryKeyIdentifier = KeyIdentifier(primaryKeyFingerprint.bytes)

    @Deprecated("Use of key-ids is discouraged.") val keyId = keyIdentifier.keyId
    val fingerprint = subkeyFingerprint

    @Deprecated("Use of key-ids is discouraged.") val subkeyId = subkeyIdentifier.keyId
    @Deprecated("Use of key-ids is discouraged.") val primaryKeyId = primaryKeyIdentifier.keyId

    val isPrimaryKey = primaryKeyIdentifier == subkeyIdentifier

    fun matches(fingerprint: OpenPgpFingerprint) =
        primaryKeyFingerprint == fingerprint || subkeyFingerprint == fingerprint

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

        return primaryKeyFingerprint == other.primaryKeyFingerprint &&
            subkeyFingerprint == other.subkeyFingerprint
    }

    override fun hashCode(): Int {
        return primaryKeyFingerprint.hashCode() + 31 * subkeyFingerprint.hashCode()
    }

    override fun toString(): String = "$subkeyFingerprint $primaryKeyFingerprint"
}
