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
package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

public class NonEmptyListTest {

    @Test
    public void testEmptyListThrows() {
        assertThrows(IllegalArgumentException.class, () -> new NonEmptyList<>(Collections.emptyList()));
    }

    @Test
    public void testSingleElementList() {
        List<String> singleElement = Collections.singletonList("Hello");
        NonEmptyList<String> nonEmpty = new NonEmptyList<>(singleElement);
        assertEquals("Hello", nonEmpty.get());
        assertTrue(nonEmpty.getOthers().isEmpty());
        assertEquals(1, nonEmpty.getAll().size());
        assertTrue(nonEmpty.getAll().contains("Hello"));
    }

    @Test
    public void testSingletonElement() {
        assertThrows(IllegalArgumentException.class, () -> new NonEmptyList<>((String) null));
        NonEmptyList<String> nonEmpty = new NonEmptyList<>("Foo");
        assertEquals("Foo", nonEmpty.get());
        assertTrue(nonEmpty.getOthers().isEmpty());
        assertEquals(Collections.singletonList("Foo"), nonEmpty.getAll());
    }

    @Test
    public void testMultipleElements() {
        List<String> multipleElements = Arrays.asList("Foo", "Bar", "Baz");
        NonEmptyList<String> nonEmpty = new NonEmptyList<>(multipleElements);
        assertEquals("Foo", nonEmpty.get());
        assertEquals(Arrays.asList("Bar", "Baz"), nonEmpty.getOthers());
        assertEquals(multipleElements, nonEmpty.getAll());
    }
}
