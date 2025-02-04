// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.bcpg.sig.KeyFlags

enum class EncryptionPurpose(val code: Int) {
    /** The stream will encrypt communication that goes over the wire. E.g. EMail, Chat... */
    COMMUNICATIONS(KeyFlags.ENCRYPT_COMMS),
    /** The stream will encrypt data at rest. E.g. Encrypted backup... */
    STORAGE(KeyFlags.ENCRYPT_STORAGE),
    /** The stream will use keys with either flags to encrypt the data. */
    ANY(KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
}
