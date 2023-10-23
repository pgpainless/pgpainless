// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

enum class StackSymbol {
    /** OpenPGP Message. */
    MSG,
    /** OnePassSignature (in case of BC this represents a OnePassSignatureList). */
    OPS,
    /** Special symbol representing the end of the message. */
    TERMINUS
}
