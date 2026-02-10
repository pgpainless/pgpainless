// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.pgpainless.key.util.UserId;

public interface Regex {

    /**
     * Return true, if the regex matches the given user-id.
     *
     * @param userId userId
     * @return true if matches, false otherwise
     */
    default boolean matches(UserId userId) {
        return matches(userId.toString());
    }

    /**
     * Return true, if the regex matches the given string.
     *
     * @param string string
     * @return true if matches, false otherwise
     */
    boolean matches(String string);

    static Regex wildcard() {
        return new Regex() {
            @Override
            public boolean matches(String string) {
                return true;
            }
        };
    }
}
