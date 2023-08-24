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
            State.OpenPgpMessage -> fromOpenPgpMessage(input, stackItem)
            State.LiteralMessage -> fromLiteralMessage(input, stackItem)
            State.CompressedMessage -> fromCompressedMessage(input, stackItem)
            State.EncryptedMessage -> fromEncryptedMessage(input, stackItem)
            State.Valid -> fromValid(input, stackItem)
            else -> throw MalformedOpenPgpMessageException(from, input, stackItem)
        }
    }

    fun fromOpenPgpMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (stackItem !== StackSymbol.msg) {
            throw MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem)
        }
        return when (input) {
            InputSymbol.LiteralData -> Transition(State.LiteralMessage)
            InputSymbol.Signature -> Transition(State.OpenPgpMessage, StackSymbol.msg)
            InputSymbol.OnePassSignature -> Transition(State.OpenPgpMessage, StackSymbol.ops, StackSymbol.msg)
            InputSymbol.CompressedData -> Transition(State.CompressedMessage)
            InputSymbol.EncryptedData -> Transition(State.EncryptedMessage)
            InputSymbol.EndOfSequence -> throw MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem)
            else -> throw MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem)
        }
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromLiteralMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.Signature && stackItem == StackSymbol.ops) {
            return Transition(State.LiteralMessage)
        }
        if (input == InputSymbol.EndOfSequence && stackItem == StackSymbol.terminus) {
            return Transition(State.Valid)
        }

        throw MalformedOpenPgpMessageException(State.LiteralMessage, input, stackItem)
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromCompressedMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.Signature && stackItem == StackSymbol.ops) {
            return Transition(State.CompressedMessage)
        }
        if (input == InputSymbol.EndOfSequence && stackItem == StackSymbol.terminus) {
            return Transition(State.Valid)
        }

        throw MalformedOpenPgpMessageException(State.CompressedMessage, input, stackItem)
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromEncryptedMessage(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.Signature && stackItem == StackSymbol.ops) {
            return Transition(State.EncryptedMessage)
        }
        if (input == InputSymbol.EndOfSequence && stackItem == StackSymbol.terminus) {
            return Transition(State.Valid)
        }

        throw MalformedOpenPgpMessageException(State.EncryptedMessage, input, stackItem)
    }

    @Throws(MalformedOpenPgpMessageException::class)
    fun fromValid(input: InputSymbol, stackItem: StackSymbol?): Transition {
        if (input == InputSymbol.EndOfSequence) {
            // allow subsequent read() calls.
            return Transition(State.Valid)
        }
        throw MalformedOpenPgpMessageException(State.Valid, input, stackItem)
    }
}