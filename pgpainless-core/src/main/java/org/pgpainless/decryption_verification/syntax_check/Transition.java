// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Result of applying a transition rule.
 * Transition rules can be described by implementing the {@link Syntax} interface.
 */
public class Transition {

    private final List<StackSymbol> pushedItems = new ArrayList<>();
    private final State newState;

    public Transition(@Nonnull State newState, @Nonnull StackSymbol... pushedItems) {
        this.newState = newState;
        this.pushedItems.addAll(Arrays.asList(pushedItems));
    }

    /**
     * Return the new {@link State} that is reached by applying the transition.
     *
     * @return new state
     */
    @Nonnull
    public State getNewState() {
        return newState;
    }

    /**
     * Return a list of {@link StackSymbol StackSymbols} that are pushed onto the stack
     * by applying the transition.
     * The list contains items in the order in which they are pushed onto the stack.
     * The list may be empty.
     *
     * @return list of items to be pushed onto the stack
     */
    @Nonnull
    public List<StackSymbol> getPushedItems() {
        return new ArrayList<>(pushedItems);
    }
}
