// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;

import static org.pgpainless.decryption_verification.syntax_check.StackSymbol.msg;
import static org.pgpainless.decryption_verification.syntax_check.StackSymbol.terminus;

public class PDA {

    private static final Logger LOGGER = LoggerFactory.getLogger(PDA.class);

    // right now we implement what rfc4880 specifies.
    // TODO: Consider implementing what we proposed here:
    //  https://mailarchive.ietf.org/arch/msg/openpgp/uepOF6XpSegMO4c59tt9e5H1i4g/
    private final Syntax syntax;
    private final Stack<StackSymbol> stack = new Stack<>();
    private final List<InputSymbol> inputs = new ArrayList<>(); // Track inputs for debugging / error reporting
    private State state;

    /**
     * Default constructor which initializes the PDA to work with the {@link OpenPgpMessageSyntax}.
     */
    public PDA() {
        this(new OpenPgpMessageSyntax(), State.OpenPgpMessage, terminus, msg);
    }

    public PDA(@Nonnull Syntax syntax, @Nonnull State initialState, @Nonnull StackSymbol... initialStack) {
        this.syntax = syntax;
        this.state = initialState;
        for (StackSymbol symbol : initialStack) {
            pushStack(symbol);
        }
    }

    public void next(InputSymbol input) throws MalformedOpenPgpMessageException {
        StackSymbol stackSymbol = popStack();
        try {
            Transition transition = syntax.transition(state, input, stackSymbol);
            state = transition.getNewState();
            for (StackSymbol item : transition.getPushedItems()) {
                pushStack(item);
            }
            inputs.add(input);
        } catch (MalformedOpenPgpMessageException e) {
            MalformedOpenPgpMessageException wrapped = new MalformedOpenPgpMessageException(
                    "Malformed message: After reading packet sequence " + Arrays.toString(inputs.toArray()) +
                    ", token '" + input + "' is not allowed." +
                    "\nNo transition from state '" + state + "' with stack " + Arrays.toString(stack.toArray()) +
                            (stackSymbol != null ? "||'" + stackSymbol + "'." : "."), e);
            LOGGER.debug("Invalid input '" + input + "'", wrapped);
            throw wrapped;
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

    public StackSymbol peekStack() {
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
    private StackSymbol popStack() {
        if (stack.isEmpty()) {
            return null;
        }
        return stack.pop();
    }

    /**
     * Push an item onto the stack.
     *
     * @param item item
     */
    private void pushStack(StackSymbol item) {
        stack.push(item);
    }

    @Override
    public String toString() {
        return "State: " + state + " Stack: " + stack;
    }
}
