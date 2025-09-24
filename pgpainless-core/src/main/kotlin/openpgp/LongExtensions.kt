// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

/** Format this Long as an OpenPGP key-ID (16 digit uppercase hex number). */
fun Long.openPgpKeyId(): String {
    return String.format("%016X", this).uppercase()
}

/** Parse a Long from a 16 digit hex encoded OpenPgp key-ID. */
fun Long.Companion.fromOpenPgpKeyId(hexKeyId: String): Long {
    require("^[0-9A-Fa-f]{16}$".toRegex().matches(hexKeyId)) {
        "Provided long key-id does not match expected format. " +
            "A long key-id consists of 16 hexadecimal characters."
    }
    // Calling toLong() only fails with a NumberFormatException.
    //  Therefore, we call toULong(16).toLong(), which seems to work.
    return hexKeyId.toULong(16).toLong()
}
