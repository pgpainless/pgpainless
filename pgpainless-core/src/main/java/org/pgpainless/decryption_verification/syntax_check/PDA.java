// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;

import static org.pgpainless.decryption_verification.syntax_check.StackSymbol.msg;
import static org.pgpainless.decryption_verification.syntax_check.StackSymbol.terminus;

public class PDA {

    private static final Logger LOGGER = LoggerFactory.getLogger(PDA.class);

    private final Stack<StackSymbol> stack = new Stack<>();
    private final List<InputSymbol> inputs = new ArrayList<>(); // keep track of inputs for debugging / error reporting
    private State state;
    private Syntax syntax = new OpenPgpMessageSyntax();

    public PDA() {
        state = State.OpenPgpMessage;
        pushStack(terminus);
        pushStack(msg);
    }

    public void next(InputSymbol input) throws MalformedOpenPgpMessageException {
        try {
            Transition transition = syntax.transition(state, input, popStack());
            inputs.add(input);
            state = transition.getNewState();
            for (StackSymbol item : transition.getPushedItems()) {
                pushStack(item);
            }
        } catch (MalformedOpenPgpMessageException e) {
            MalformedOpenPgpMessageException wrapped = new MalformedOpenPgpMessageException("Malformed message: After reading stream " + Arrays.toString(inputs.toArray()) +
                    ", token '" + input + "' is unexpected and illegal.", e);
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
