// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

import org.pgpainless.exception.MalformedOpenPgpMessageException
import org.slf4j.LoggerFactory

/**
 * Pushdown Automaton for validating context-free languages. In PGPainless, this class is used to
 * validate OpenPGP message packet sequences against the allowed syntax.
 *
 * See [OpenPGP Message Syntax](https://www.rfc-editor.org/rfc/rfc4880#section-11.3)
 */
class PDA
constructor(
    private val syntax: Syntax,
    private val stack: ArrayDeque<StackSymbol>,
    private val inputs: MutableList<InputSymbol>,
    private var state: State
) {

    /**
     * Construct a PDA with a custom [Syntax], initial [State] and initial
     * [StackSymbols][StackSymbol].
     *
     * @param syntax syntax
     * @param initialState initial state
     * @param initialStack zero or more initial stack items (get pushed onto the stack in order of
     *   appearance)
     */
    constructor(
        syntax: Syntax,
        initialState: State,
        vararg initialStack: StackSymbol
    ) : this(syntax, ArrayDeque(initialStack.toList().reversed()), mutableListOf(), initialState)

    /** Default constructor which initializes the PDA to work with the [OpenPgpMessageSyntax]. */
    constructor() :
        this(OpenPgpMessageSyntax(), State.OPENPGP_MESSAGE, StackSymbol.TERMINUS, StackSymbol.MSG)

    /**
     * Process the next [InputSymbol]. This will either leave the PDA in the next state, or throw a
     * [MalformedOpenPgpMessageException] if the input symbol is rejected.
     *
     * @param input input symbol
     * @throws MalformedOpenPgpMessageException if the input symbol is rejected
     */
    fun next(input: InputSymbol) {
        val stackSymbol = popStack()
        try {
            val transition = syntax.transition(state, input, stackSymbol)
            state = transition.newState
            for (item in transition.pushedItems) {
                pushStack(item)
            }
            inputs.add(input)
        } catch (e: MalformedOpenPgpMessageException) {
            val stackFormat =
                if (stackSymbol != null) {
                    "${stack.joinToString()}||$stackSymbol"
                } else {
                    stack.joinToString()
                }
            val wrapped =
                MalformedOpenPgpMessageException(
                    "Malformed message: After reading packet sequence ${inputs.joinToString()}, token '$input' is not allowed.\n" +
                        "No transition from state '$state' with stack $stackFormat",
                    e)
            LOGGER.debug("Invalid input '$input'", wrapped)
            throw wrapped
        }
    }

    /**
     * Peek at the stack, returning the topmost stack item without changing the stack.
     *
     * @return topmost stack item, or null if stack is empty
     */
    fun peekStack(): StackSymbol? = stack.firstOrNull()

    /**
     * Return true, if the PDA is in a valid state (the OpenPGP message is valid).
     *
     * @return true if valid, false otherwise
     */
    fun isValid(): Boolean = state == State.VALID && stack.isEmpty()

    /**
     * Throw a [MalformedOpenPgpMessageException] if the pda is not in a valid state right now.
     *
     * @throws MalformedOpenPgpMessageException if the pda is not in an acceptable state
     */
    fun assertValid() {
        if (!isValid()) {
            throw MalformedOpenPgpMessageException(
                "Pushdown Automaton is not in an acceptable state: ${toString()}")
        }
    }

    /**
     * Pop an item from the stack.
     *
     * @return stack item
     */
    private fun popStack(): StackSymbol? {
        return stack.removeFirstOrNull()
    }

    /**
     * Push an item onto the stack.
     *
     * @param item item
     */
    private fun pushStack(item: StackSymbol) {
        stack.addFirst(item)
    }

    override fun toString(): String {
        return "State: $state Stack: ${stack.joinToString()}"
    }

    companion object {
        @JvmStatic private val LOGGER = LoggerFactory.getLogger(PDA::class.java)
    }
}
