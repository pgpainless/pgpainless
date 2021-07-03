/*
 * Copyright 2018 Paul Schaub.
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

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
        assertTrue(multiMap.get("alice").contains("wonderland"));
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
        map.put("test", "foo");
        assertFalse(map.isEmpty());
        map.clear();
        assertTrue(map.isEmpty());
    }

    @Test
    public void addTwoRemoveOneWorks() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("alice", "wonderland");
        map.put("bob", "builder");
        map.removeAll("alice");

        assertFalse(map.containsKey("alice"));
        assertNull(map.get("alice"));
        assertFalse(map.isEmpty());
    }

    @Test
    public void addMultiValue() {
        MultiMap<String, String> addOneByOne = new MultiMap<>();
        addOneByOne.put("foo", "bar");
        addOneByOne.put("foo", "baz");

        MultiMap<String, String> addOnce = new MultiMap<>();
        addOnce.put("foo", new HashSet<>(Arrays.asList("baz", "bar")));

        assertEquals(addOneByOne, addOnce);
    }

    @Test
    public void addMultiValueRemoveSingle() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("foo", "bar");
        map.put("foo", "baz");

        map.remove("foo", "bar");
        assertFalse(map.isEmpty());
        assertTrue(map.containsKey("foo"));
        assertEquals(Collections.singleton("baz"), map.get("foo"));
    }

    @Test
    public void addMultiValueRemoveAll() {
        MultiMap<String, String> map = new MultiMap<>();
        map.put("foo", "bar");
        map.put("foo", "baz");
        map.put("bingo", "bango");

        map.removeAll("foo");
        assertFalse(map.isEmpty());
        assertFalse(map.containsKey("foo"));
        assertTrue(map.containsKey("bingo"));
    }
}
