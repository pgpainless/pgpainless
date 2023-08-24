// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

import org.pgpainless.exception.MalformedOpenPgpMessageException

/**
 * This class describes the syntax for OpenPGP messages as specified by rfc4880.
 *
 * See [rfc4880 - §11.3. OpenPGP Messages](https://www.rfc-editor.org/rfc/rfc4880#section-11.3)
 * See [Blog post about theoretic background and translation of grammar to PDA syntax](https://blog.jabberhead.tk/2022/09/14/using-pushdown-automata-to-verify-packet-sequences/)
 * See [Blog post about practically implementing the PDA for packet syntax validation](https://blog.jabberhead.tk/2022/10/26/implementing-packet-sequence-validation-using-pushdown-automata/)
 */
class OpenPgpMessageSyntax : Syntax {

    override fun transition(from: State, input: InputSymbol, stackItem: StackSymbol?): Transition {
        return when (from) {
            State.OPENPGP_MESSAGE -> fromOpenPgpMessage(input, stackItem)
            State.LITERAL_MESSAGE -> fromLiteralMessage(input, stackItem)
            State.COMPRESSED_MESSAGE -> fromCompressedMessage(input, stackItem)
            State.ENCRYPTED_MESSAGE -> fromEncryptedMessage(input, stackItem)
            State.VALID -> fromValid(input, stackItem)
            else -> throw MalformedOpenPgpMessageException(from, input, stackItem)
        }
    }

    fun fromOpenPgpMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (stackItem !== StackSymbol.MSG) {
            throw MalformedOpenPgpMessageException(State.OPENPGP_MESSAGE, input, stackItem)
        }
        return when (input) {
            InputSymbol.LITERAL_DATA -> Transition(State.LITERAL_MESSAGE)
            InputSymbol.SIGNATURE -> Transition(State.OPENPGP_MESSAGE, StackSymbol.MSG)
            InputSymbol.ONE_PASS_SIGNATURE -> Transition(State.OPENPGP_MESSAGE, StackSymbol.OPS, StackSymbol.MSG)
            InputSymbol.COMPRESSED_DATA -> Transition(State.COMPRESSED_MESSAGE)
            InputSymbol.ENCRYPTED_DATA -> Transition(State.ENCRYPTED_MESSAGE)
            InputSymbol.END_OF_SEQUENCE -> throw MalformedOpenPgpMessageException(State.OPENPGP_MESSAGE, input, stackItem)
            else -> throw MalformedOpenPgpMessageException(State.OPENPGP_MESSAGE, input, stackItem)
        }
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromLiteralMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.SIGNATURE && stackItem == StackSymbol.OPS) {
            return Transition(State.LITERAL_MESSAGE)
        }
        if (input == InputSymbol.END_OF_SEQUENCE && stackItem == StackSymbol.TERMINUS) {
            return Transition(State.VALID)
        }

        throw MalformedOpenPgpMessageException(State.LITERAL_MESSAGE, input, stackItem)
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromCompressedMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.SIGNATURE && stackItem == StackSymbol.OPS) {
            return Transition(State.COMPRESSED_MESSAGE)
        }
        if (input == InputSymbol.END_OF_SEQUENCE && stackItem == StackSymbol.TERMINUS) {
            return Transition(State.VALID)
        }

        throw MalformedOpenPgpMessageException(State.COMPRESSED_MESSAGE, input, stackItem)
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromEncryptedMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.SIGNATURE && stackItem == StackSymbol.OPS) {
            return Transition(State.ENCRYPTED_MESSAGE)
        }
        if (input == InputSymbol.END_OF_SEQUENCE && stackItem == StackSymbol.TERMINUS) {
            return Transition(State.VALID)
        }

        throw MalformedOpenPgpMessageException(State.ENCRYPTED_MESSAGE, input, stackItem)
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromValid(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.END_OF_SEQUENCE) {
            // allow subsequent read() calls.
            return Transition(State.VALID)
        }
        throw MalformedOpenPgpMessageException(State.VALID, input, stackItem)
    }
}