// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import org.pgpainless.decryption_verification.syntax_check.InputSymbol
import org.pgpainless.decryption_verification.syntax_check.StackSymbol
import org.pgpainless.decryption_verification.syntax_check.State

/**
 * Exception that gets thrown if the OpenPGP message is malformed. Malformed messages are messages
 * which do not follow the grammar specified in the RFC.
 *
 * @see [RFC4880 §11.3. OpenPGP Messages](https://www.rfc-editor.org/rfc/rfc4880#section-11.3)
 */
class MalformedOpenPgpMessageException : RuntimeException {
    constructor(message: String?) : super(message)

    constructor(message: String, e: MalformedOpenPgpMessageException) : super(message, e)

    constructor(
        state: State,
        input: InputSymbol,
        stackItem: StackSymbol?
    ) : this(
        "There is no legal transition from state '$state' for input '$input' when '${stackItem ?: "null"}' is on top of the stack.",
    )
}
