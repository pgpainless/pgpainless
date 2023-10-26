// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

class MultiMap<K, V> : Iterable<Map.Entry<K, Set<V>>> {

    private val map: Map<K, MutableSet<V>>

    constructor() : this(mutableMapOf())

    constructor(other: MultiMap<K, V>) : this(other.map)

    constructor(content: Map<K, Set<V>>) {
        map = mutableMapOf()
        content.forEach { map[it.key] = it.value.toMutableSet() }
    }

    override fun iterator(): Iterator<Map.Entry<K, Set<V>>> {
        return map.iterator()
    }

    val size: Int
        get() = map.size

    fun size() = size

    val keys: Set<K>
        get() = map.keys

    fun keySet() = keys

    val values: Collection<Set<V>>
        get() = map.values

    fun values() = values

    val entries: Set<Map.Entry<K, Set<V>>>
        get() = map.entries

    fun entrySet() = entries

    fun isEmpty(): Boolean = map.isEmpty()

    fun containsKey(key: K): Boolean = map.containsKey(key)

    fun containsValue(value: V): Boolean = map.values.any { it.contains(value) }

    fun contains(key: K, value: V): Boolean = map[key]?.contains(value) ?: false

    operator fun get(key: K): Set<V>? = map[key]

    fun put(key: K, value: V) = (map as MutableMap).put(key, mutableSetOf(value))

    fun plus(key: K, value: V) = (map as MutableMap).getOrPut(key) { mutableSetOf() }.add(value)

    fun put(key: K, values: Set<V>) = (map as MutableMap).put(key, values.toMutableSet())

    fun plus(key: K, values: Set<V>) =
        (map as MutableMap).getOrPut(key) { mutableSetOf() }.addAll(values)

    fun putAll(other: MultiMap<K, V>) = other.map.entries.forEach { put(it.key, it.value) }

    fun plusAll(other: MultiMap<K, V>) = other.map.entries.forEach { plus(it.key, it.value) }

    fun removeAll(key: K) = (map as MutableMap).remove(key)

    fun remove(key: K, value: V) = (map as MutableMap)[key]?.remove(value)

    fun clear() = (map as MutableMap).clear()

    fun flatten() = map.flatMap { it.value }.toSet()

    override fun equals(other: Any?): Boolean {
        return if (other == null) false
        else if (other !is MultiMap<*, *>) false
        else if (this === other) {
            true
        } else {
            map == other.map
        }
    }

    override fun hashCode(): Int {
        return map.hashCode()
    }
}
