// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;

public class OpenPgpMessageSyntax implements Syntax {

    @Override
    public Transition transition(State from, InputAlphabet input, StackAlphabet stackItem)
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

    Transition fromOpenPgpMessage(InputAlphabet input, StackAlphabet stackItem)
            throws MalformedOpenPgpMessageException {
        if (stackItem != StackAlphabet.msg) {
            throw new MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem);
        }

        switch (input) {
            case LiteralData:
                return new Transition(State.LiteralMessage);

            case Signature:
                return new Transition(State.OpenPgpMessage, StackAlphabet.msg);

            case OnePassSignature:
                return new Transition(State.OpenPgpMessage, StackAlphabet.ops, StackAlphabet.msg);

            case CompressedData:
                return new Transition(State.CompressedMessage);

            case EncryptedData:
                return new Transition(State.EncryptedMessage);

            case EndOfSequence:
            default:
                throw new MalformedOpenPgpMessageException(State.OpenPgpMessage, input, stackItem);
        }
    }

    Transition fromLiteralMessage(InputAlphabet input, StackAlphabet stackItem)
            throws MalformedOpenPgpMessageException {
        switch (input) {
            case Signature:
                if (stackItem == StackAlphabet.ops) {
                    return new Transition(State.LiteralMessage);
                }
                break;

            case EndOfSequence:
                if (stackItem == StackAlphabet.terminus) {
                    return new Transition(State.Valid);
                }
                break;
        }

        throw new MalformedOpenPgpMessageException(State.LiteralMessage, input, stackItem);
    }

    Transition fromCompressedMessage(InputAlphabet input, StackAlphabet stackItem)
            throws MalformedOpenPgpMessageException {
        switch (input) {
            case Signature:
                if (stackItem == StackAlphabet.ops) {
                    return new Transition(State.CompressedMessage);
                }
                break;

            case EndOfSequence:
                if (stackItem == StackAlphabet.terminus) {
                    return new Transition(State.Valid);
                }
                break;
        }

        throw new MalformedOpenPgpMessageException(State.CompressedMessage, input, stackItem);
    }

    Transition fromEncryptedMessage(InputAlphabet input, StackAlphabet stackItem)
            throws MalformedOpenPgpMessageException {
        switch (input) {
            case Signature:
                if (stackItem == StackAlphabet.ops) {
                    return new Transition(State.EncryptedMessage);
                }
                break;

            case EndOfSequence:
                if (stackItem == StackAlphabet.terminus) {
                    return new Transition(State.Valid);
                }
                break;
        }

        throw new MalformedOpenPgpMessageException(State.EncryptedMessage, input, stackItem);
    }

    Transition fromValid(InputAlphabet input, StackAlphabet stackItem)
            throws MalformedOpenPgpMessageException {
        throw new MalformedOpenPgpMessageException(State.Valid, input, stackItem);
    }
}
