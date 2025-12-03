// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import com.basistech.tclre.HsrePattern;
import com.basistech.tclre.PatternFlags;
import com.basistech.tclre.RePattern;
import com.basistech.tclre.RegexException;

public class HSRegexInterpreterFactory extends RegexInterpreterFactory {

    public Regex instantiate(String regex) {
        return new Regex() {

            private final RePattern pattern;

            {
                try {
                    pattern = HsrePattern.compile(regex, PatternFlags.ADVANCED);
                } catch (RegexException e) {
                    throw new IllegalArgumentException(e);
                }
            }

            @Override
            public boolean matches(String string) {
                return pattern.matcher(string).find();
            }
        };
    }
}
