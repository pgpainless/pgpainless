// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey

/**
 * Return the [OpenPGPSecretKey] that can be used to decrypt the given [PGPPublicKeyEncryptedData].
 *
 * @param pkesk public-key encrypted session-key packet
 * @return secret key or null if no matching secret key was found
 */
fun OpenPGPKey.getSecretKeyFor(pkesk: PGPPublicKeyEncryptedData): OpenPGPSecretKey? =
    this.getSecretKey(pkesk.keyIdentifier)

fun OpenPGPComponentKey.getSecretKey(): OpenPGPSecretKey? =
    if (this.certificate is OpenPGPKey) {
        (this.certificate as OpenPGPKey).getSecretKey(this)
    } else {
        null
    }

fun OpenPGPKey.isFullyDecrypted(): Boolean {
    return secretKeys.values.none { it.isLocked }
}

fun OpenPGPKey.isFullyEncrypted(): Boolean {
    return secretKeys.values.all { it.isLocked }
}
