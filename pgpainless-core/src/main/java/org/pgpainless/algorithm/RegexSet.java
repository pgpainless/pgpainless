// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class RegexSet {

    private final Set<Regex> regexSet = new HashSet<>();

    private RegexSet(Collection<Regex> regexes) {
        this.regexSet.addAll(regexes);
    }

    public static RegexSet matchAnything() {
        return new RegexSet(Collections.singleton(Regex.wildcard()));
    }

    public static RegexSet matchNothing() {
        return new RegexSet(Collections.emptySet());
    }

    public static RegexSet matchSome(Collection<Regex> regexes) {
        return new RegexSet(regexes);
    }

    public boolean matches(String userId) {
        for (Regex regex : regexSet) {
            if (regex.matches(userId)) {
                return true;
            }
        }
        return false;
    }
}
