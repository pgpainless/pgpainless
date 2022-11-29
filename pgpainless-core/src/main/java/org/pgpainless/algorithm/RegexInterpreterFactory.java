// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import javax.annotation.Nonnull;
import java.util.regex.Pattern;

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
