// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey

/** This class represents a hex encoded uppercase OpenPGP v5 fingerprint. */
class OpenPgpV5Fingerprint : _64DigitFingerprint {

    constructor(fingerprint: String) : super(fingerprint)

    constructor(key: PGPPublicKey) : super(key)

    constructor(key: PGPSecretKey) : super(key)

    constructor(keys: PGPKeyRing) : super(keys)

    constructor(bytes: ByteArray) : super(bytes)

    override fun getVersion(): Int {
        return 5
    }
}
