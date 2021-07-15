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
