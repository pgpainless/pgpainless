// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class NotationRegistryTest {

    @Test
    public void notationIsKnownOnceAddedAndUnknownOnceCleared() {
        NotationRegistry registry = new NotationRegistry();

        assertFalse(registry.isKnownNotation("proof@metacode.biz"), "Notation is initially not known.");
        assertFalse(registry.isKnownNotation("unkown@notation.data"));

        registry.addKnownNotation("proof@metacode.biz");
        assertTrue(registry.isKnownNotation("proof@metacode.biz"), "Notation is known after it has been added to the registry.");
        assertFalse(registry.isKnownNotation("unknown@notation.data"));

        registry.clear();
        assertFalse(registry.isKnownNotation("proof@metacode.biz"), "Notation is no longer known after registry is cleared.");
        assertFalse(registry.isKnownNotation("unknown@notation.data"));
    }

    @Test
    public void addKnownNotation_nullThrows() {
        NotationRegistry registry = new NotationRegistry();
        assertThrows(NullPointerException.class, () -> registry.addKnownNotation(null));
    }
}
