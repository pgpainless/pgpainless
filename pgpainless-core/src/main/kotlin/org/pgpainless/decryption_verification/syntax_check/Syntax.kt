// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

import org.pgpainless.exception.MalformedOpenPgpMessageException

/**
 * This interface can be used to define a custom syntax for the [PDA].
 */
interface Syntax {

    /**
     * Describe a transition rule from [State] <pre>from</pre> for [InputSymbol] <pre>input</pre>
     * with [StackSymbol] <pre>stackItem</pre> from the top of the [PDAs][PDA] stack.
     * The resulting [Transition] contains the new [State], as well as a list of
     * [StackSymbols][StackSymbol] that get pushed onto the stack by the transition rule.
     * If there is no applicable rule, a [MalformedOpenPgpMessageException] is thrown, since in this case
     * the [InputSymbol] must be considered illegal.
     *
     * @param from current state of the PDA
     * @param input input symbol
     * @param stackItem item that got popped from the top of the stack
     * @return applicable transition rule containing the new state and pushed stack symbols
     * @throws MalformedOpenPgpMessageException if there is no applicable transition rule (the input symbol is illegal)
     */
    @Throws(MalformedOpenPgpMessageException::class)
    fun transition(from: State, input: InputSymbol, stackItem: StackSymbol?): Transition
}