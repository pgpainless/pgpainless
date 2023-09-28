// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class MultiMapTest {

    @Test
    public void isEmptyAfterCreation() {
        MultiMap<String, String> map = new MultiMap<>();
        assertTrue(map.isEmpty());
        assertNull(map.get("alice"));
        assertFalse(map.containsKey("alice"));
        assertFalse(map.containsValue("wonderland"));
        assertEquals(0, map.size());
    }

    @Test
    public void addOneElement_works() {
        MultiMap<String, String> multiMap = new MultiMap<>();

        multiMap.put("alice", "wonderland");
        assertFalse(multiMap.isEmpty());
        assertEquals(1, multiMap.size());
        assertTrue(multiMap.containsKey("alice"));
        assertTrue(multiMap.containsValue("wonderland"));
        assertNotNull(multiMap.get("alice"));
        assertTrue(multiMap.contains("alice", "wonderland"));
    }

    @Test
    public void putOverwritesExistingElements() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("alice", "wonderland");
        map.put("alice", "whothefrickisalice");
        assertFalse(map.containsValue("wonderland"));
    }

    @Test
    public void plusDoesNotOverwriteButAdd() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("alice", "wonderland");
        map.plus("alice", "whothefrickisalice");
        assertTrue(map.containsValue("wonderland"));
        assertTrue(map.containsValue("whothefrickisalice"));
    }

    @Test
    public void containsWorks() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("alice", "wonderland");
        map.plus("alice", "bar");
        map.put("bob", "builder");

        assertTrue(map.contains("alice", "wonderland"));
        assertTrue(map.contains("alice", "bar"));
        assertTrue(map.contains("bob", "builder"));
        assertFalse(map.contains("bob", "bar"));
    }

    @Test
    public void addTwoKeys_OneWithTwoValues_works() {
        MultiMap<String, String> multiMap = new MultiMap<>();

        multiMap.put("alice", "wonderland");
        multiMap.put("mad", new HashSet<>(Arrays.asList("hatter", "max")));

        assertEquals(2, multiMap.size());
        assertEquals(new HashSet<>(Arrays.asList("alice", "mad")), multiMap.keySet());
        assertEquals(new HashSet<>(Arrays.asList("hatter", "max")), multiMap.get("mad"));
        assertEquals(
                new HashSet<>(Arrays.asList(
                        Collections.singleton("wonderland"),
                        new HashSet<>(Arrays.asList("hatter", "max")
                        ))),
                new HashSet<>(multiMap.values()));

        assertEquals(Collections.singleton("wonderland"), multiMap.get("alice"));
        assertEquals(new HashSet<>(Arrays.asList("hatter", "max")), multiMap.get("mad"));
    }

    @Test
    public void emptyEqualsEmptyTest() {
        MultiMap<String, String> emptyOne = new MultiMap<>();
        MultiMap<String, String> emptyTwo = new MultiMap<>();
        assertEquals(emptyOne, emptyTwo);
    }

    @Test
    public void notEqualsNull() {
        MultiMap<String, String> map = new MultiMap<>();
        assertNotEquals(map, null);
    }

    @Test
    public void selfEquals() {
        MultiMap<String, String> map = new MultiMap<>();
        assertEquals(map, map);
    }

    @Test
    public void otherClassNotEquals() {
        MultiMap<String, String> map = new MultiMap<>();
        assertNotEquals(map, "String");
    }

    @Test
    public void mapEqualsCopy() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("foo", "bar");
        map.put("entries", new HashSet<>(Arrays.asList("one", "two")));

        MultiMap<String, String> copy = new MultiMap<>(map);

        assertEquals(map, copy);
    }

    @Test
    public void emptyAfterClear() {
        MultiMap<String, String> map = new MultiMap<>();
        map.plus("test", "foo");
        assertFalse(map.isEmpty());
        map.clear();
        assertTrue(map.isEmpty());
    }

    @Test
    public void addTwoRemoveOneWorks() {
        MultiMap<String, String> map = new MultiMap<>();
        map.plus("alice", "wonderland");
        map.plus("bob", "builder");
        map.removeAll("alice");

        assertFalse(map.containsKey("alice"));
        assertNull(map.get("alice"));
        assertFalse(map.isEmpty());
    }

    @Test
    public void addMultiValue() {
        MultiMap<String, String> addOneByOne = new MultiMap<>();
        addOneByOne.plus("foo", "bar");
        addOneByOne.plus("foo", "baz");

        MultiMap<String, String> addOnce = new MultiMap<>();
        addOnce.plus("foo", new HashSet<>(Arrays.asList("baz", "bar")));

        assertEquals(addOneByOne, addOnce);
    }

    @Test
    public void addMultiValueRemoveSingle() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("foo", "bar");
        map.plus("foo", "baz");

        map.remove("foo", "bar");
        assertFalse(map.isEmpty());
        assertTrue(map.containsKey("foo"));
        assertEquals(Collections.singleton("baz"), map.get("foo"));
    }

    @Test
    public void addMultiValueRemoveAll() {
        MultiMap<String, String> map = new MultiMap<>();
        map.plus("foo", "bar");
        map.plus("foo", "baz");
        map.plus("bingo", "bango");

        map.removeAll("foo");
        assertFalse(map.isEmpty());
        assertFalse(map.containsKey("foo"));
        assertTrue(map.containsKey("bingo"));
    }

    @Test
    public void plusAll() {
        MultiMap<String, String> map = new MultiMap<>();
        map.plus("A", "1");
        map.plus("A", "2");
        map.plus("B", "1");

        MultiMap<String, String> other = new MultiMap<>();
        other.plus("A", "1");
        other.plus("B", "2");
        other.plus("C", "3");

        map.plusAll(other);
        assertTrue(map.contains("A", "1"));
        assertTrue(map.contains("A", "2"));
        assertTrue(map.contains("B", "1"));
        assertTrue(map.contains("B", "2"));
        assertTrue(map.contains("C", "3"));
    }

    @Test
    public void flattenEmptyMap() {
        MultiMap<String, String> empty = new MultiMap<>();
        assertEquals(Collections.emptySet(), empty.flatten());
    }

    @Test
    public void flattenMap() {
        MultiMap<String, String> map = new MultiMap<>();
        map.plus("A", "1");
        map.plus("A", "2");
        map.plus("B", "1");

        Set<String> expected = new LinkedHashSet<>();
        expected.add("1");
        expected.add("2");
        assertEquals(expected, map.flatten());
    }
}
