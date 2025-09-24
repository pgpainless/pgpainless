// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPException

class WrongPassphraseException : PGPException {

    constructor(message: String) : super(message)

    constructor(message: String, cause: PGPException) : super(message, cause)

    @Deprecated("Pass in a KeyIdentifier instead.")
    constructor(keyId: Long, cause: PGPException) : this(KeyIdentifier(keyId), cause)

    constructor(
        keyIdentifier: KeyIdentifier,
        cause: PGPException
    ) : this("Wrong passphrase provided for key $keyIdentifier", cause)
}
