/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.util;

import java.math.BigInteger;
import java.util.regex.Pattern;

public class KeyIdUtil {

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
