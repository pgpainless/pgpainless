// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * This class describes the syntax for OpenPGP messages as specified by rfc4880.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-11.3">
 *     rfc4880 - §11.3. OpenPGP Messages</a>
 * @see <a href="https://blog.jabberhead.tk/2022/09/14/using-pushdown-automata-to-verify-packet-sequences/">
 *     Blog post about theoretic background and translation of grammar to PDA syntax</a>
 * @see <a href="https://blog.jabberhead.tk/2022/10/26/implementing-packet-sequence-validation-using-pushdown-automata/">
 *     Blog post about practically implementing the PDA for packet syntax validation</a>
 */
public class OpenPgpMessageSyntax implements Syntax {

    @Override
    public @Nonnull Transition transition(@Nonnull State from, @Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
            throws MalformedOpenPgpMessageException {
        switch (from) {
            case OpenPgpMessage:
                return fromOpenPgpMessage(input, stackItem);
            case LiteralMessage:
                return fromLiteralMessage(input, stackItem);
            case CompressedMessage:
                return fromCompressedMessage(input, stackItem);
            case EncryptedMessage:
                return fromEncryptedMessage(input, stackItem);
            case Valid:
                return fromValid(input, stackItem);
        }

        throw new MalformedOpenPgpMessageException(from, input, stackItem);
    }

    @Nonnull
    Transition fromOpenPgpMessage(@Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
            throws MalformedOpenPgpMessageException {
        if (stackItem != StackSymbol.msg) {
            throw new MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem);
        }

        switch (input) {
            case LiteralData:
                return new Transition(State.LiteralMessage);

            case Signature:
                return new Transition(State.OpenPgpMessage, StackSymbol.msg);

            case OnePassSignature:
                return new Transition(State.OpenPgpMessage, StackSymbol.ops, StackSymbol.msg);

            case CompressedData:
                return new Transition(State.CompressedMessage);

            case EncryptedData:
                return new Transition(State.EncryptedMessage);

            case EndOfSequence:
            default:
                throw new MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem);
        }
    }

    @Nonnull
    Transition fromLiteralMessage(@Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
            throws MalformedOpenPgpMessageException {
        switch (input) {
            case Signature:
                if (stackItem == StackSymbol.ops) {
                    return new Transition(State.LiteralMessage);
                }
                break;

            case EndOfSequence:
                if (stackItem == StackSymbol.terminus) {
                    return new Transition(State.Valid);
                }
                break;
        }

        throw new MalformedOpenPgpMessageException(State.LiteralMessage, input, stackItem);
    }

    @Nonnull
    Transition fromCompressedMessage(@Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
            throws MalformedOpenPgpMessageException {
        switch (input) {
            case Signature:
                if (stackItem == StackSymbol.ops) {
                    return new Transition(State.CompressedMessage);
                }
                break;

            case EndOfSequence:
                if (stackItem == StackSymbol.terminus) {
                    return new Transition(State.Valid);
                }
                break;
        }

        throw new MalformedOpenPgpMessageException(State.CompressedMessage, input, stackItem);
    }

    @Nonnull
    Transition fromEncryptedMessage(@Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
            throws MalformedOpenPgpMessageException {
        switch (input) {
            case Signature:
                if (stackItem == StackSymbol.ops) {
                    return new Transition(State.EncryptedMessage);
                }
                break;

            case EndOfSequence:
                if (stackItem == StackSymbol.terminus) {
                    return new Transition(State.Valid);
                }
                break;
        }

        throw new MalformedOpenPgpMessageException(State.EncryptedMessage, input, stackItem);
    }

    @Nonnull
    Transition fromValid(@Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
            throws MalformedOpenPgpMessageException {
        if (input == InputSymbol.EndOfSequence) {
            // allow subsequent read() calls.
            return new Transition(State.Valid);
        }
        // There is no applicable transition rule out of Valid
        throw new MalformedOpenPgpMessageException(State.Valid, input, stackItem);
    }
}
