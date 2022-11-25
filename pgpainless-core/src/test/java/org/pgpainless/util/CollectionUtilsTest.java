// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Test;

public class CollectionUtilsTest {

    @Test
    public void testConcat() {
        String a = "A";
        String[] bc = new String[] {"B", "C"};

        String[] abc = CollectionUtils.concat(a, bc);
        assertArrayEquals(new String[] {"A", "B", "C"}, abc);
    }

    @Test
    public void testConcatWithEmptyArray() {
        String a = "A";
        String[] empty = new String[0];

        String[] concat = CollectionUtils.concat(a, empty);
        assertArrayEquals(new String[] {"A"}, concat);
    }

    @Test
    public void iteratorToListTest() {
        List<String> list = Arrays.asList("A", "B", "C");
        Iterator<String> iterator = list.iterator();

        List<String> listFromIterator = CollectionUtils.iteratorToList(iterator);
        assertEquals(list, listFromIterator);
    }

    @Test
    public void iteratorToList_emptyIteratorTest() {
        Iterator<String> iterator = Collections.emptyIterator();

        List<String> listFromIterator = CollectionUtils.iteratorToList(iterator);
        assertTrue(listFromIterator.isEmpty());
    }

    @Test
    public void containsTest() {
        String[] abc = new String[] {"A", "B", "C"};

        assertTrue(CollectionUtils.contains(abc, "A"));
        assertTrue(CollectionUtils.contains(abc, "B"));
        assertTrue(CollectionUtils.contains(abc, "C"));
        assertFalse(CollectionUtils.contains(abc, "D"));
    }

    @Test
    public void contains_emptyTest() {
        String[] empty = new String[0];

        assertFalse(CollectionUtils.contains(empty, "A"));
    }

    @Test
    public void addAllTest() {
        List<String> list = new ArrayList<>();
        list.add("A");
        list.add("B");

        List<String> other = new ArrayList<>();
        other.add("C");
        other.add("D");
        Iterator<String> iterator = other.iterator();

        CollectionUtils.addAll(iterator, list);

        assertEquals(Arrays.asList("A", "B", "C", "D"), list);
    }

    @Test
    public void addAllEmptyListTest() {
        List<String> empty = new ArrayList<>();

        List<String> other = Arrays.asList("A", "B", "C");
        Iterator<String> iterator = other.iterator();

        CollectionUtils.addAll(iterator, empty);
        assertEquals(Arrays.asList("A", "B", "C"), empty);
    }

    @Test
    public void addAllEmptyIterator() {
        List<String> list = new ArrayList<>();
        list.add("A");
        list.add("B");

        Iterator<String> iterator = Collections.emptyIterator();

        CollectionUtils.addAll(iterator, list);
        assertEquals(Arrays.asList("A", "B"), list);
    }
}
