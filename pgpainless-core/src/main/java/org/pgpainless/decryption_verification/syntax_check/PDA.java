// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Stack;

import static org.pgpainless.decryption_verification.syntax_check.StackAlphabet.msg;
import static org.pgpainless.decryption_verification.syntax_check.StackAlphabet.ops;
import static org.pgpainless.decryption_verification.syntax_check.StackAlphabet.terminus;

public class PDA {

    private static int ID = 0;
    private static final Logger LOGGER = LoggerFactory.getLogger(PDA.class);

    /**
     * Set of states of the automaton.
     * Each state defines its valid transitions in their {@link State#transition(InputAlphabet, PDA)} method.
     */
    public enum State {

        OpenPgpMessage {
            @Override
            State transition(InputAlphabet input, PDA automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                if (stackItem != msg) {
                    throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
                switch (input) {

                    case LiteralData:
                        return LiteralMessage;

                    case Signature:
                        automaton.pushStack(msg);
                        return OpenPgpMessage;

                    case OnePassSignature:
                        automaton.pushStack(ops);
                        automaton.pushStack(msg);
                        return OpenPgpMessage;

                    case CompressedData:
                        return CompressedMessage;

                    case EncryptedData:
                        return EncryptedMessage;

                    case EndOfSequence:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        LiteralMessage {
            @Override
            State transition(InputAlphabet input, PDA automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                switch (input) {

                    case Signature:
                        if (stackItem == ops) {
                            return LiteralMessage;
                        } else {
                            throw new MalformedOpenPgpMessageException(this, input, stackItem);
                        }

                    case EndOfSequence:
                        if (stackItem == terminus && automaton.stack.isEmpty()) {
                            return Valid;
                        } else {
                            throw new MalformedOpenPgpMessageException(this, input, stackItem);
                        }

                    case LiteralData:
                    case OnePassSignature:
                    case CompressedData:
                    case EncryptedData:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        CompressedMessage {
            @Override
            State transition(InputAlphabet input, PDA automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                switch (input) {
                    case Signature:
                        if (stackItem == ops) {
                            return CompressedMessage;
                        } else {
                            throw new MalformedOpenPgpMessageException(this, input, stackItem);
                        }

                    case EndOfSequence:
                        if (stackItem == terminus && automaton.stack.isEmpty()) {
                            return Valid;
                        } else {
                            throw new MalformedOpenPgpMessageException(this, input, stackItem);
                        }

                    case LiteralData:
                    case OnePassSignature:
                    case CompressedData:
                    case EncryptedData:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        EncryptedMessage {
            @Override
            State transition(InputAlphabet input, PDA automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                switch (input) {
                    case Signature:
                        if (stackItem == ops) {
                            return EncryptedMessage;
                        } else {
                            throw new MalformedOpenPgpMessageException(this, input, stackItem);
                        }

                    case EndOfSequence:
                        if (stackItem == terminus && automaton.stack.isEmpty()) {
                            return Valid;
                        } else {
                            throw new MalformedOpenPgpMessageException(this, input, stackItem);
                        }

                    case LiteralData:
                    case OnePassSignature:
                    case CompressedData:
                    case EncryptedData:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        Valid {
            @Override
            State transition(InputAlphabet input, PDA automaton) throws MalformedOpenPgpMessageException {
                throw new MalformedOpenPgpMessageException(this, input, null);
            }
        },
        ;

        /**
         * Pop the automatons stack and transition to another state.
         * If no valid transition from the current state is available given the popped stack item and input symbol,
         * a {@link MalformedOpenPgpMessageException} is thrown.
         * Otherwise, the stack is manipulated according to the valid transition and the new state is returned.
         *
         * @param input     input symbol
         * @param automaton automaton
         * @return new state of the automaton
         * @throws MalformedOpenPgpMessageException in case of an illegal input symbol
         */
        abstract State transition(InputAlphabet input, PDA automaton) throws MalformedOpenPgpMessageException;
    }

    private final Stack<StackAlphabet> stack = new Stack<>();
    private State state;
    private int id;

    public PDA() {
        state = State.OpenPgpMessage;
        stack.push(terminus);
        stack.push(msg);
        this.id = ID++;
    }

    public void next(InputAlphabet input) throws MalformedOpenPgpMessageException {
        try {
            state = state.transition(input, this);
        } catch (MalformedOpenPgpMessageException e) {
            LOGGER.debug("Unexpected Packet or Token '" + input + "' encountered. Message is malformed.", e);
            throw e;
        }
    }

    /**
     * Return the current state of the PDA.
     *
     * @return state
     */
    public State getState() {
        return state;
    }

    public StackAlphabet peekStack() {
        if (stack.isEmpty()) {
            return null;
        }
        return stack.peek();
    }

    /**
     * Return true, if the PDA is in a valid state (the OpenPGP message is valid).
     *
     * @return true if valid, false otherwise
     */
    public boolean isValid() {
        return getState() == State.Valid && stack.isEmpty();
    }

    public void assertValid() throws MalformedOpenPgpMessageException {
        if (!isValid()) {
            throw new MalformedOpenPgpMessageException("Pushdown Automaton is not in an acceptable state: " + toString());
        }
    }

    /**
     * Pop an item from the stack.
     *
     * @return stack item
     */
    private StackAlphabet popStack() {
        return stack.pop();
    }

    /**
     * Push an item onto the stack.
     *
     * @param item item
     */
    private void pushStack(StackAlphabet item) {
        stack.push(item);
    }

    @Override
    public String toString() {
        return "PDA " + id + ": State: " + state + " Stack: " + stack;
    }
}
