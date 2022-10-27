// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Transition {

    private final List<StackAlphabet> pushedItems = new ArrayList<>();
    private final State newState;

    public Transition(State newState, StackAlphabet... pushedItems) {
        this.newState = newState;
        this.pushedItems.addAll(Arrays.asList(pushedItems));
    }

    public State getNewState() {
        return newState;
    }

    public List<StackAlphabet> getPushedItems() {
        return new ArrayList<>(pushedItems);
    }
}
