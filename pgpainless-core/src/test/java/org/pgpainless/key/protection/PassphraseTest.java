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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    public void testTrimming() {
        Passphrase leadingSpace = Passphrase.fromPassword(" space");
        assertArrayEquals("space".toCharArray(), leadingSpace.getChars());
        assertFalse(leadingSpace.isEmpty());

        Passphrase trailingSpace = Passphrase.fromPassword("space ");
        assertArrayEquals("space".toCharArray(), trailingSpace.getChars());
        assertFalse(trailingSpace.isEmpty());

        Passphrase leadingTrailingWhitespace = new Passphrase("\t Such whitespace, much wow\n ".toCharArray());
        assertArrayEquals("Such whitespace, much wow".toCharArray(), leadingTrailingWhitespace.getChars());
        assertFalse(leadingTrailingWhitespace.isEmpty());

        Passphrase fromEmptyChars = new Passphrase("     ".toCharArray());
        assertNull(fromEmptyChars.getChars());
        assertTrue(fromEmptyChars.isEmpty());
    }

    @Test
    public void testEmptyPassphrase() {
        Passphrase empty = Passphrase.emptyPassphrase();
        assertNull(empty.getChars());
        assertTrue(empty.isEmpty());

        Passphrase trimmedEmpty = Passphrase.fromPassword("    ");
        assertNull(trimmedEmpty.getChars());
        assertTrue(trimmedEmpty.isEmpty());
    }

    @Test
    public void equalsTest() {
        assertNotEquals(Passphrase.fromPassword("passphrase"), Passphrase.fromPassword("Password"));
        assertNotEquals(Passphrase.fromPassword("password"), null);
        assertNotEquals(Passphrase.fromPassword("password"), "password");
        Passphrase passphrase = Passphrase.fromPassword("passphrase");
        assertEquals(passphrase, passphrase);
    }

    @Test
    public void hashCodeTest() {
        assertNotEquals(0, Passphrase.fromPassword("passphrase").hashCode());
        assertNotEquals(Passphrase.fromPassword("passphrase").hashCode(), Passphrase.fromPassword("password").hashCode());
        assertEquals(0, Passphrase.emptyPassphrase().hashCode());
    }
}
