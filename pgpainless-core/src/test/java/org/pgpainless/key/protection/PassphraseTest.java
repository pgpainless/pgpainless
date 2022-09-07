// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.pgpainless.s2k.Passphrase;

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

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "  ", "\t", "\t\t"})
    public void testEmptyPassphrases(String empty) {
        Passphrase passphrase = Passphrase.fromPassword(empty);
        assertTrue(passphrase.isEmpty());

        assertEquals(Passphrase.emptyPassphrase(), passphrase);
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
