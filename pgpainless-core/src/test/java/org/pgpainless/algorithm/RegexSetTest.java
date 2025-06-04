// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class RegexSetTest {

    @Test
    public void matchNothingTest() {
        RegexSet set = RegexSet.matchNothing();
        assertFalse(set.matches("<alice@pgpainless.org>"));
        assertFalse(set.matches("Alice"));
        assertFalse(set.matches("Alice <alice@pgpainless.org>"));
        assertFalse(set.matches(""));
    }

    @Test
    public void matchAnything() {
        RegexSet set = RegexSet.matchAnything();
        assertTrue(set.matches("Alice"));
        assertTrue(set.matches("<alice@pgpainless.org>"));
        assertTrue(set.matches("Alice <alice@pgpainless.org>"));
        assertTrue(set.matches("Alice <alice@example.org>"));
        assertTrue(set.matches(""));
    }

    @Test
    public void matchSome() {
        Regex pgpainless_org = RegexInterpreterFactory.createDefaultMailDomainRegex("pgpainless.org");
        Regex example_org = RegexInterpreterFactory.createDefaultMailDomainRegex("example.org");

        RegexSet set = RegexSet.matchSome(Arrays.asList(pgpainless_org, example_org));
        assertTrue(set.matches("Alice <alice@pgpainless.org>"));
        assertTrue(set.matches("<alice@pgpainless.org>"));
        assertTrue(set.matches("Bob <bob@example.org>"));
        assertTrue(set.matches("<bob@example.org>"));
        assertFalse(set.matches("Bob <bob@example.com>"));
        assertFalse(set.matches("Alice <alice@PGPainless.org>"));
        assertFalse(set.matches("alice@pgpainless.org"));
        assertFalse(set.matches("Alice"));
        assertFalse(set.matches(""));
    }
}
