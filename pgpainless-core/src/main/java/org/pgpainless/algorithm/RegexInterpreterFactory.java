// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.regex.Pattern;
import javax.annotation.Nonnull;

public abstract class RegexInterpreterFactory {

    private static RegexInterpreterFactory INSTANCE;

    public static RegexInterpreterFactory getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new JavaRegexInterpreterFactory();
        }
        return INSTANCE;
    }

    public static void setInstance(@Nonnull RegexInterpreterFactory instance) {
        INSTANCE = instance;
    }

    public static Regex create(String regex) {
        return getInstance().instantiate(regex);
    }

    /**
     * Regex that matches any mail address on the given mail server.
     * For example, calling this method with parameter <pre>pgpainless.org</pre> will return a regex
     * that matches any of the following user ids:
     * <pre>
     *     Alice <alice@pgpainless.org>
     *     <bob@pgpainless.org>
     *     Issuer (code signing) <issuer@pgpainless.org>
     * </pre>
     * It will however not match the following mail addresses:
     * <pre>
     *     Alice <alice@example.org>
     *     alice@pgpainless.org
     *     alice@pgpainless.org <alice@example.org>
     *     Bob <bob@PGPainless.org>
     * </pre>
     * Note: This method will not validate the given domain string, so that is your responsibility!
     *
     * @param mailDomain domain
     * @return regex matching the domain
     */
    public static Regex createDefaultMailDomainRegex(String mailDomain) {
        String escaped = mailDomain.replace(".", "\\.");
        return create("<[^>]+[@.]" + escaped + ">$");
    }

    public abstract Regex instantiate(String regex) throws IllegalArgumentException;

    public static class JavaRegexInterpreterFactory extends RegexInterpreterFactory {

        @Override
        public Regex instantiate(String regex) {
            return new Regex() {

                private final Pattern pattern = Pattern.compile(regex);

                @Override
                public boolean matches(String string) {
                    return pattern.matcher(string).find();
                }
            };
        }
    }
}
