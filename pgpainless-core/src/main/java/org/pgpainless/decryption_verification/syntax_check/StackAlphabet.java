// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

public enum StackAlphabet {
    /**
     * OpenPGP Message.
     */
    msg,
    /**
     * OnePassSignature (in case of BC this represents a OnePassSignatureList).
     */
    ops,
    /**
     * ESK. Not used, as BC combines encrypted data with their encrypted session keys.
     */
    esk,
    /**
     * Special symbol representing the end of the message.
     */
    terminus
}
