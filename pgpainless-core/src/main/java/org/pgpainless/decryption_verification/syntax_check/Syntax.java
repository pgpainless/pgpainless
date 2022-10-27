// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * This interface can be used to define a custom syntax for the {@link PDA}.
 */
public interface Syntax {

    /**
     * Describe a transition rule from {@link State} <pre>from</pre> for {@link InputSymbol} <pre>input</pre>
     * with {@link StackSymbol} <pre>stackItem</pre> from the top of the {@link PDA PDAs} stack.
     * The resulting {@link Transition} contains the new {@link State}, as well as a list of
     * {@link StackSymbol StackSymbols} that get pushed onto the stack by the transition rule.
     * If there is no applicable rule, a {@link MalformedOpenPgpMessageException} is thrown, since in this case
     * the {@link InputSymbol} must be considered illegal.
     *
     * @param from current state of the PDA
     * @param input input symbol
     * @param stackItem item that got popped from the top of the stack
     * @return applicable transition rule containing the new state and pushed stack symbols
     * @throws MalformedOpenPgpMessageException if there is no applicable transition rule (the input symbol is illegal)
     */
    @Nonnull Transition transition(@Nonnull State from, @Nonnull InputSymbol input, @Nullable StackSymbol stackItem)
        throws MalformedOpenPgpMessageException;
}
