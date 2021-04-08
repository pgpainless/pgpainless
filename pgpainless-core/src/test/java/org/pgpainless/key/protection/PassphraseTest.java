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
package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.pgpainless.util.Passphrase;

public class PassphraseTest {

    @Test
    public void testGetAndClear() {
        Passphrase passphrase = new Passphrase("secret".toCharArray());

        assertArrayEquals("secret".toCharArray(), passphrase.getChars());
        assertTrue(passphrase.isValid());

        passphrase.clear();

        assertFalse(passphrase.isValid());
        assertThrows(IllegalStateException.class, passphrase::getChars);
    }

    @Test
    public void testFromPasswordNull() {
        Passphrase passphrase = Passphrase.fromPassword(null);
        assertArrayEquals(null, passphrase.getChars());
        assertTrue(passphrase.isValid());
    }
}
