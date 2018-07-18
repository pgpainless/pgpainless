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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class MultiMap<K, V> {

    private final Map<K, Set<V>> map;

    public MultiMap() {
        map = new HashMap<>();
    }

    public MultiMap(MultiMap<K, V> other) {
        this.map = new HashMap<>();
        for (K k : other.map.keySet()) {
            map.put(k, new HashSet<>(other.map.get(k)));
        }
    }

    public MultiMap(Map<K, Set<V>> content) {
        this.map = new HashMap<>(content);
    }

    public int size() {
        return map.size();
    }

    public boolean isEmpty() {
        return map.isEmpty();
    }

    public boolean containsKey(Object o) {
        return map.containsKey(o);
    }

    public boolean containsValue(Object o) {
        for (Set<V> values : map.values()) {
            if (values.contains(o)) return true;
        }
        return false;
    }

    public Set<V> get(Object o) {
        return map.get(o);
    }

    public void put(K k, V v) {
        Set<V> values = map.get(k);
        if (values == null) {
            values = new HashSet<>();
            map.put(k, values);
        }
        values.add(v);
    }

    public void put(K k, Set<V> vs) {
        for (V v : vs) {
            put(k, v);
        }
    }

    public void remove(Object o) {
        for (Set<V> values : map.values()) {
            values.remove(o);
        }
    }

    public void putAll(Map<? extends K, ? extends Set<V>> _map) {
        for (K key : _map.keySet()) {
            Set<V> vs = this.map.get(key);
            if (vs == null) {
                vs = new HashSet<>();
                this.map.put(key, vs);
            }
            vs.addAll(_map.get(key));
        }
    }

    public void clear() {
        map.clear();
    }

    public Set<K> keySet() {
        return map.keySet();
    }

    public Collection<Set<V>> values() {
        return map.values();
    }

    public Set<Map.Entry<K, Set<V>>> entrySet() {
        return map.entrySet();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (!(o instanceof MultiMap)) {
            return false;
        }

        if (this == o) {
            return true;
        }

        return map.equals(((MultiMap) o).map);
    }

    @Override
    public int hashCode() {
        return map.hashCode();
    }
}
