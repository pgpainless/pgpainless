// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class OptionalTest {

    @Test
    public void testEmpty() {
        Optional<String> optional = new Optional<>();
        assertEmpty(optional);
    }

    @Test
    public void testArg() {
        String string = "foo";
        Optional<String> optional = new Optional<>(string);
        assertFalse(optional.isEmpty());
        assertTrue(optional.isPresent());
        assertEquals(string, optional.get());
    }

    @Test
    public void testOfEmpty() {
        Optional<String> optional = Optional.ofEmpty();
        assertEmpty(optional);
    }

    @Test
    public void testNullArg() {
        Optional<String> optional = new Optional<>(null);
        assertEmpty(optional);
    }

    @Test
    public void testOfWithNullArgThrows() {
        assertThrows(NullPointerException.class, () -> Optional.of(null));
    }

    @Test
    public void testOf() {
        String string = "Hello, World!";
        Optional<String> optional = Optional.of(string);
        assertFalse(optional.isEmpty());
        assertTrue(optional.isPresent());
        assertEquals(string, optional.get());
    }

    @Test
    public void testOfNullableWithNull() {
        Optional<String> optional = Optional.ofNullable(null);
        assertEmpty(optional);
    }

    @Test
    public void testOfNullableWithArg() {
        Optional<String> optional = Optional.ofNullable("bar");
        assertEquals("bar", optional.get());
        assertFalse(optional.isEmpty());
        assertTrue(optional.isPresent());
    }

    private <T> void assertEmpty(Optional<T> optional) {
        assertTrue(optional.isEmpty());
        assertFalse(optional.isPresent());

        assertNull(optional.get());
    }
}
