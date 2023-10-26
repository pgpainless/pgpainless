// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

/** Set of states of the automaton. */
enum class State {
    OPENPGP_MESSAGE,
    LITERAL_MESSAGE,
    COMPRESSED_MESSAGE,
    ENCRYPTED_MESSAGE,
    VALID
}
