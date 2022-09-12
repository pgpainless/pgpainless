package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.exception.MalformedOpenPgpMessageException;

import java.util.Stack;

import static org.pgpainless.decryption_verification.PushdownAutomaton.StackAlphabet.msg;
import static org.pgpainless.decryption_verification.PushdownAutomaton.StackAlphabet.ops;
import static org.pgpainless.decryption_verification.PushdownAutomaton.StackAlphabet.terminus;

/**
 * Pushdown Automaton to verify the correct syntax of OpenPGP messages during decryption.
 * <p>
 * OpenPGP messages MUST follow certain rules in order to be well-formed.
 * Section §11.3. of RFC4880 specifies a formal grammar for OpenPGP messages.
 * <p>
 * This grammar was transformed into a pushdown automaton, which is implemented below.
 * The automaton only ends up in a valid state ({@link #isValid()} iff the OpenPGP message conformed to the
 * grammar.
 * <p>
 * There are some specialties with this implementation though:
 * Bouncy Castle combines ESKs and Encrypted Data Packets into a single object, so we do not have to
 * handle those manually.
 * <p>
 * Bouncy Castle further combines OnePassSignatures and Signatures into lists, so instead of pushing multiple
 * 'o's onto the stack repeatedly, a sequence of OnePassSignatures causes a single 'o' to be pushed to the stack.
 * The same is true for Signatures.
 * <p>
 * Therefore, a message is valid, even if the number of OnePassSignatures and Signatures does not match.
 * If a message contains at least one OnePassSignature, it is sufficient if there is at least one Signature to
 * not cause a {@link MalformedOpenPgpMessageException}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-11.3">RFC4880 §11.3. OpenPGP Messages</a>
 */
public class PushdownAutomaton {

    public enum InputAlphabet {
        /**
         * A {@link PGPLiteralData} packet.
         */
        LiteralData,
        /**
         * A {@link PGPSignatureList} object.
         */
        Signatures,
        /**
         * A {@link PGPOnePassSignatureList} object.
         */
        OnePassSignatures,
        /**
         * A {@link PGPCompressedData} packet.
         * The contents of this packet MUST form a valid OpenPGP message, so a nested PDA is opened to verify
         * its nested packet sequence.
         */
        CompressedData,
        /**
         * A {@link PGPEncryptedDataList} object.
         * This object combines multiple ESKs and the corresponding Symmetrically Encrypted
         * (possibly Integrity Protected) Data packet.
         */
        EncryptedData,
        /**
         * Marks the end of a (sub-) sequence.
         * This input is given if the end of an OpenPGP message is reached.
         * This might be the case for the end of the whole ciphertext, or the end of a packet with nested contents
         * (e.g. the end of a Compressed Data packet).
         */
        EndOfSequence
    }

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

    /**
     * Set of states of the automaton.
     * Each state defines its valid transitions in their {@link State#transition(InputAlphabet, PushdownAutomaton)}
     * method.
     */
    public enum State {

        OpenPgpMessage {
            @Override
            State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                if (stackItem != msg) {
                    throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
                switch (input) {

                    case LiteralData:
                        return LiteralMessage;

                    case Signatures:
                        automaton.pushStack(msg);
                        return OpenPgpMessage;

                    case OnePassSignatures:
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
            State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                switch (input) {

                    case Signatures:
                        if (stackItem == ops) {
                            return CorrespondingSignature;
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
                    case OnePassSignatures:
                    case CompressedData:
                    case EncryptedData:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        CompressedMessage {
            @Override
            State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                switch (input) {
                    case Signatures:
                        if (stackItem == ops) {
                            return CorrespondingSignature;
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
                    case OnePassSignatures:
                    case CompressedData:
                    case EncryptedData:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        EncryptedMessage {
            @Override
            State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                switch (input) {
                    case Signatures:
                        if (stackItem == ops) {
                            return CorrespondingSignature;
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
                    case OnePassSignatures:
                    case CompressedData:
                    case EncryptedData:
                    default:
                        throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        CorrespondingSignature {
            @Override
            State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException {
                StackAlphabet stackItem = automaton.popStack();
                if (stackItem == terminus && input == InputAlphabet.EndOfSequence && automaton.stack.isEmpty()) {
                    return Valid;
                } else {
                    throw new MalformedOpenPgpMessageException(this, input, stackItem);
                }
            }
        },

        Valid {
            @Override
            State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException {
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
        abstract State transition(InputAlphabet input, PushdownAutomaton automaton) throws MalformedOpenPgpMessageException;
    }

    private final Stack<StackAlphabet> stack = new Stack<>();
    private State state;
    // Some OpenPGP packets have nested contents (e.g. compressed / encrypted data).
    PushdownAutomaton nestedSequence = null;

    public PushdownAutomaton() {
        state = State.OpenPgpMessage;
        stack.push(terminus);
        stack.push(msg);
    }

    /**
     * Process the next input packet.
     *
     * @param input input
     * @throws MalformedOpenPgpMessageException in case the input packet is illegal here
     */
    public void next(InputAlphabet input) throws MalformedOpenPgpMessageException {
        _next(input);
    }

    /**
     * Process the next input packet.
     * This method returns true, iff the given input triggered a successful closing of this PDAs nested PDA.
     * <p>
     * This is for example the case, if the current packet is a Compressed Data packet which contains a
     * valid nested OpenPGP message and the last input was {@link InputAlphabet#EndOfSequence} indicating the
     * end of the Compressed Data packet.
     * <p>
     * If the input triggered this PDAs nested PDA to close its nested PDA, this method returns false
     * in order to prevent this PDA from closing its nested PDA prematurely.
     *
     * @param input input
     * @return true if this just closed its nested sequence, false otherwise
     * @throws MalformedOpenPgpMessageException if the input is illegal
     */
    private boolean _next(InputAlphabet input) throws MalformedOpenPgpMessageException {
        if (nestedSequence != null) {
            boolean sequenceInNestedSequenceWasClosed = nestedSequence._next(input);
            if (sequenceInNestedSequenceWasClosed) return false; // No need to close out nested sequence too.
        } else {
            // make a state transition in this automaton
            state = state.transition(input, this);

            // If the processed packet contains nested sequence, open nested automaton for it
            if (input == InputAlphabet.CompressedData || input == InputAlphabet.EncryptedData) {
                nestedSequence = new PushdownAutomaton();
            }
        }

        if (input != InputAlphabet.EndOfSequence) {
            return false;
        }

        // Close nested sequence if needed
        boolean nestedIsInnerMost = nestedSequence != null && nestedSequence.isInnerMost();
        if (nestedIsInnerMost) {
            if (nestedSequence.isValid()) {
                // Close nested sequence
                nestedSequence = null;
                return true;
            } else {
                throw new MalformedOpenPgpMessageException("Climbing up nested message validation failed." +
                        " Automaton for current nesting level is not in valid state: " + nestedSequence.getState() + " " + nestedSequence.stack.peek() + " (Input was " + input + ")");
            }
        }
        return false;
    }

    /**
     * Return the current state of the PDA.
     *
     * @return state
     */
    private State getState() {
        return state;
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

    /**
     * Return true, if this packet sequence has no nested sequence.
     * A nested sequence is for example the content of a Compressed Data packet.
     *
     * @return true if PDA is innermost, false if it has a nested sequence
     */
    private boolean isInnerMost() {
        return nestedSequence == null;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder("State: ").append(state)
                .append(", Stack (asc.): ").append(stack)
                .append('\n');
        if (nestedSequence != null) {
            // recursively call toString() on nested PDAs and indent their representation
            String nestedToString = nestedSequence.toString();
            String[] lines = nestedToString.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String nestedLine = lines[i];
                out.append(i == 0 ? "⤷ " : "  ") // indent nested PDA
                        .append(nestedLine)
                        .append('\n');
            }
        }
        return out.toString();
    }
}
