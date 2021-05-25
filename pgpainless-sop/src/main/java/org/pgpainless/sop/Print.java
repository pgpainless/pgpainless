/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.sop;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.util.ArmorUtils;

public class Print {

    public static String toString(PGPSecretKeyRing keyRing, boolean armor) throws IOException {
        if (armor) {
            return ArmorUtils.toAsciiArmoredString(keyRing);
        } else {
            return new String(keyRing.getEncoded(), "UTF-8");
        }
    }

    public static String toString(PGPPublicKeyRing keyRing, boolean armor) throws IOException {
        if (armor) {
            return ArmorUtils.toAsciiArmoredString(keyRing);
        } else {
            return new String(keyRing.getEncoded(), "UTF-8");
        }
    }

    public static String toString(byte[] bytes, boolean armor) throws IOException {
        if (armor) {
            return ArmorUtils.toAsciiArmoredString(bytes);
        } else {
            return new String(bytes, "UTF-8");
        }
    }

    public static void print_ln(String msg) {
        // CHECKSTYLE:OFF
        System.out.println(msg);
        // CHECKSTYLE:ON
    }

    public static void err_ln(String msg) {
        // CHECKSTYLE:OFF
        System.err.println(msg);
        // CHECKSTYLE:ON
    }
}
