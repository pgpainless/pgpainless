// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HSRegexInterpreterFactoryTest {

    @Test
    public void dummyRegexTest() {
        HSRegexInterpreterFactory factory = new HSRegexInterpreterFactory();
        RegexInterpreterFactory.setInstance(factory);
        Regex regex = RegexInterpreterFactory.create("Alice|Bob");

        assertTrue(regex.matches("Alice"));
        assertTrue(regex.matches("Bob"));
        assertFalse(regex.matches("Charlie"));
    }
}
