// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey

fun OpenPGPKey.getSecretKeyFor(pkesk: PGPPublicKeyEncryptedData): OpenPGPSecretKey? =
    this.getSecretKey(pkesk.keyIdentifier)
