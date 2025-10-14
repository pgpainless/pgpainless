// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey
import org.pgpainless.util.Passphrase

/**
 * Return the [OpenPGPSecretKey] that can be used to decrypt the given [PGPPublicKeyEncryptedData].
 *
 * @param pkesk public-key encrypted session-key packet
 * @return secret key or null if no matching secret key was found
 */
fun OpenPGPKey.getSecretKeyFor(pkesk: PGPPublicKeyEncryptedData): OpenPGPSecretKey? =
    this.getSecretKey(pkesk.keyIdentifier)

/**
 * Unlock the [OpenPGPSecretKey], returning the unlocked [OpenPGPPrivateKey].
 *
 * @param passphrase passphrase to unlock the key
 * @return unlocked [OpenPGPPrivateKey]
 */
fun OpenPGPSecretKey.unlock(passphrase: Passphrase): OpenPGPPrivateKey =
    this.unlock(passphrase.getChars())

fun OpenPGPKey.isFullyDecrypted(): Boolean {
    return secretKeys.values.none { it.isLocked }
}

fun OpenPGPKey.isFullyEncrypted(): Boolean {
    return secretKeys.values.all { it.isLocked }
}
