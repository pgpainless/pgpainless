// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

/**
 * Result of applying a transition rule. Transition rules can be described by implementing the
 * [Syntax] interface.
 *
 * @param newState new [State] that is reached by applying the transition.
 * @param pushedItems list of [StackSymbol] that are pushed onto the stack by applying the
 *   transition. The list contains items in the order in which they are pushed onto the stack. The
 *   list may be empty.
 */
class Transition private constructor(val pushedItems: List<StackSymbol>, val newState: State) {

    constructor(
        newState: State,
        vararg pushedItems: StackSymbol
    ) : this(pushedItems.toList(), newState)
}
