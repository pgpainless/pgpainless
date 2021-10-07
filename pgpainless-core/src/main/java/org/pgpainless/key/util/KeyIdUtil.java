// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import java.math.BigInteger;
import java.util.regex.Pattern;

public final class KeyIdUtil {

    private KeyIdUtil() {

    }

    private static final Pattern LONG_KEY_ID = Pattern.compile("^[0-9A-Fa-f]{16}$");

    /**
     * Convert a long key-id into a key-id.
     * A long key-id is a 16 digit hex string.
     *
     * @param longKeyId 16-digit hexadecimal string
     * @return key-id converted to {@link Long}.
     */
    public static long fromLongKeyId(String longKeyId) {
        if (!LONG_KEY_ID.matcher(longKeyId).matches()) {
            throw new IllegalArgumentException("Provided long key-id does not match expected format. " +
                    "A long key-id consists of 16 hexadecimal characters.");
        }

        return new BigInteger(longKeyId, 16).longValue();
    }
}
