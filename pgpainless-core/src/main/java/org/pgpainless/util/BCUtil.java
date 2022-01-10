// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

public final class BCUtil {

    private BCUtil() {

    }

    /**
     * A constant time equals comparison - does not terminate early if
     * test will fail. For best results always pass the expected value
     * as the first parameter.
     *
     * @param expected first array
     * @param supplied second array
     * @return true if arrays equal, false otherwise.
     */
    public static boolean constantTimeAreEqual(
            char[]  expected,
            char[]  supplied) {
        if (expected == null || supplied == null) {
            return false;
        }

        if (expected == supplied) {
            return true;
        }

        int len = Math.min(expected.length, supplied.length);

        int nonEqual = expected.length ^ supplied.length;

        // do the char-wise comparison
        for (int i = 0; i != len; i++) {
            nonEqual |= (expected[i] ^ supplied[i]);
        }
        // If supplied is longer than expected, iterate over rest of supplied with NOPs
        for (int i = len; i < supplied.length; i++) {
            nonEqual |= ((byte) supplied[i] ^ (byte) ~supplied[i]);
        }

        return nonEqual == 0;
    }

}
