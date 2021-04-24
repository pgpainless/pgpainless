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
package org.pgpainless.algorithm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPLiteralData;

/**
 * Encoding of the stream.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.9">RFC4880: Literal Data Packet</a>
 */
public enum StreamEncoding {
    BINARY(PGPLiteralData.BINARY),
    TEXT(PGPLiteralData.TEXT),
    UTF8(PGPLiteralData.UTF8),
    @Deprecated
    LOCAL('l'),
    ;

    private final char code;

    private static final Map<Character, StreamEncoding> MAP = new ConcurrentHashMap<>();
    static {
        for (StreamEncoding f : StreamEncoding.values()) {
            MAP.put(f.code, f);
        }
        MAP.put('1', LOCAL);
    }

    StreamEncoding(char code) {
        this.code = code;
    }

    public char getCode() {
        return code;
    }

    public static StreamEncoding fromCode(int code) {
        return MAP.get((char) code);
    }
}
