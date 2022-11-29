// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.key.util.UserId;

public class RegexTest {
    private static Stream<Arguments> provideRegexInterpreterFactories() {
        return Stream.of(
                Arguments.of(Named.of("Default JavaRegexInterpreterFactory",
                        new RegexInterpreterFactory.JavaRegexInterpreterFactory())),
                Arguments.of(Named.of("HSRegexInterpreterFactory",
                        new HSRegexInterpreterFactory()))
        );
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void simpleTest(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate("Alice|Bob");
        assertTrue(regex.matches("Alice"));
        assertTrue(regex.matches("Bob"));
        assertFalse(regex.matches("Charlie"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testEmailRegexMatchesDomain(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate("<[^>]+[@.]pgpainless\\.org>$");
        assertTrue(regex.matches("Alice <alice@pgpainless.org>"));
        assertTrue(regex.matches("Bob <bob@pgpainless.org>"));
        assertFalse(regex.matches("Alice <alice@example.com>"), "wrong domain");
        assertFalse(regex.matches("Bob <bob@example.com>"), "wrong domain");
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testEmailRegexMatchesOnlyWrappedAddresses(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate("<[^>]+[@.]pgpainless\\.org>$");
        assertTrue(regex.matches("<alice@pgpainless.org>"));
        assertFalse(regex.matches("alice@pgpainless.org"), "only match mails in <>");
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testCaseSensitivity(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate("<[^>]+[@.]pgpainless\\.org>$");
        assertFalse(regex.matches("Alice <alice@PGPAINLESS.ORG>"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testWildCard(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate(".*");
        assertTrue(regex.matches(""));
        assertTrue(regex.matches("Alice"));
        assertTrue(regex.matches("<alice@pgpainless.org>"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testExclusion(RegexInterpreterFactory factory) {
        // Test [^>] matches all but '>'
        Regex regex = factory.instantiate("<[^>]+[@.]pgpainless\\.org>$");
        assertFalse(regex.matches("<alice>appendix@pgpainless.org>"));
        assertFalse(regex.matches("<>alice@pgpainless.org>"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testOnlyMatchAtTheEnd(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate("<[^>]+[@.]pgpainless\\.org>$");
        assertFalse(regex.matches("Alice <alice@pgpainless.org><bob@example.org>"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testRanges(RegexInterpreterFactory factory) {
        Regex regex = factory.instantiate("<[^>]+[0-9][@.]pgpainless\\.org>$");

        for (int i = 0; i < 10; i++) {
            String mail = "<user" + i + "@pgpainless.org>";
            assertTrue(regex.matches(mail));
        }

        assertFalse(regex.matches("<user@pgpainless.org>"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testExactMailMatch(RegexInterpreterFactory factory) {
        Regex exactMail = factory.instantiate("<exact@pgpainless\\.org>$");
        assertTrue(exactMail.matches("<exact@pgpainless.org>"));
        assertTrue(exactMail.matches("Exact Match <exact@pgpainless.org>"));
        assertFalse(exactMail.matches("<roughly-exact@pgpainless.org>"));
    }

    @ParameterizedTest
    @MethodSource("provideRegexInterpreterFactories")
    public void testSetInstance(RegexInterpreterFactory factory) {
        RegexInterpreterFactory before = RegexInterpreterFactory.getInstance();
        RegexInterpreterFactory.setInstance(factory);

        Regex regex = RegexInterpreterFactory.create("<[^>]+[@.]pgpainless\\.org>$");
        assertTrue(regex.matches(UserId.nameAndEmail("Alice", "alice@pgpainless.org")));

        RegexInterpreterFactory.setInstance(before);
    }
}
