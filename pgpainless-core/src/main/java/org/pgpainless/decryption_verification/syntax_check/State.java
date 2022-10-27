// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

/**
 * Set of states of the automaton.
 */
public enum State {
    OpenPgpMessage,
    LiteralMessage,
    CompressedMessage,
    EncryptedMessage,
    Valid
}
