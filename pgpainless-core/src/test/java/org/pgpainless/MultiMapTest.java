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
package org.pgpainless;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertNull;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.pgpainless.util.MultiMap;

public class MultiMapTest {

    @Test
    public void test() {
        MultiMap<String, String> multiMap = new MultiMap<>();
        assertTrue(multiMap.isEmpty());
        assertNull(multiMap.get("alice"));
        assertFalse(multiMap.containsKey("alice"));
        assertFalse(multiMap.containsValue("wonderland"));
        assertEquals(0, multiMap.size());

        multiMap.put("alice", "wonderland");
        assertFalse(multiMap.isEmpty());
        assertEquals(1, multiMap.size());
        assertTrue(multiMap.containsKey("alice"));
        assertTrue(multiMap.containsValue("wonderland"));
        assertNotNull(multiMap.get("alice"));
        assertTrue(multiMap.get("alice").contains("wonderland"));

        multiMap.put("mad", new HashSet<>(Arrays.asList("hatter", "max")));
        assertEquals(new HashSet<>(Arrays.asList("hatter", "max")), multiMap.get("mad"));

        assertEquals(new HashSet<>(Arrays.asList("mad", "alice")), multiMap.keySet());
        assertEquals(new HashSet<>(Arrays.asList(
                Collections.singleton("wonderland"),
                new HashSet<>(Arrays.asList("hatter", "max")))), new HashSet<>(multiMap.values()));

        Set<Map.Entry<String, Set<String>>> entries = multiMap.entrySet();
        assertEquals(2, entries.size());
        for (Map.Entry<String, Set<String>> e : entries) {
            switch (e.getKey()) {
                case "alice":
                    assertEquals(1, e.getValue().size());
                    assertTrue(e.getValue().contains("wonderland"));
                    break;
                case "mad":
                    assertEquals(2, e.getValue().size());
                    assertTrue(e.getValue().contains("hatter"));
                    assertTrue(e.getValue().contains("max"));
                    break;
                default:
                    fail("Illegal key.");
                    break;
            }
        }

        MultiMap<String, String> empty = new MultiMap<>();
        assertFalse(multiMap.equals(empty));
        assertEquals(multiMap, multiMap);
        assertFalse(multiMap.equals(null));

        MultiMap<String, String> map2 = new MultiMap<>();
        map2.put("alice", "schwarzer");
        map2.put("dr", "strange");

        multiMap.putAll(map2);
        assertTrue(multiMap.containsKey("dr"));
        assertEquals(1, multiMap.get("dr").size());
        assertTrue(multiMap.get("dr").contains("strange"));
        assertTrue(multiMap.containsKey("mad"));
        assertEquals(2, multiMap.get("alice").size());
        assertTrue(multiMap.get("alice").contains("wonderland"));
        assertTrue(multiMap.get("alice").contains("schwarzer"));

        multiMap.removeAll("mad");
        assertFalse(multiMap.containsKey("mad"));
        assertNull(multiMap.get("mad"));

        multiMap.remove("alice", "wonderland");
        assertFalse(multiMap.containsValue("wonderland"));
        assertTrue(multiMap.containsKey("alice"));
        assertEquals(1, multiMap.get("alice").size());
        assertTrue(multiMap.get("alice").contains("schwarzer"));

        MultiMap<String, String> copy = new MultiMap<>(multiMap);
        assertEquals(multiMap, copy);

        copy.removeAll("inexistent");
        assertEquals(multiMap, copy);

        copy.remove("inexistent", "schwarzer");
        assertEquals(multiMap, copy);

        assertEquals(multiMap.hashCode(), copy.hashCode());

        copy.clear();
        assertTrue(copy.isEmpty());

        Map<String, Set<String>> map = new HashMap<>();
        map.put("key", Collections.singleton("value"));

        MultiMap<String, String> fromMap = new MultiMap<>(map);
        assertFalse(fromMap.isEmpty());
        assertEquals(fromMap.get("key"), Collections.singleton("value"));

        assertFalse(fromMap.equals(map));
    }
}
