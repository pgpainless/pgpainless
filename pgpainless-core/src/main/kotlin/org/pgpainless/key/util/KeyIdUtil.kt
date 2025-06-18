// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util

import openpgp.fromOpenPgpKeyId
import openpgp.openPgpKeyId

class KeyIdUtil {

    companion object {

        /**
         * Convert a long key-id into a key-id. A long key-id is a 16 digit hex string.
         *
         * @param longKeyId 16-digit hexadecimal string
         * @return key-id converted to [Long].
         */
        @JvmStatic fun fromLongKeyId(longKeyId: String) = Long.fromOpenPgpKeyId(longKeyId)

        /**
         * Format a long key-ID as upper-case hex string.
         *
         * @param keyId keyId
         * @return hex encoded key ID
         */
        @JvmStatic
        @Deprecated("Superseded by Long extension method.", ReplaceWith("keyId.hexKeyId()"))
        fun formatKeyId(keyId: Long) = keyId.openPgpKeyId()
    }
}
