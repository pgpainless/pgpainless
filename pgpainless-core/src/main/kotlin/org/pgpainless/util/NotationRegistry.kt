// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

/**
 * Registry for known notations. Since signature verification must reject signatures with critical
 * notations that are not known to the application, there must be some way to tell PGPainless which
 * notations actually are known.
 *
 * To add a notation name, call {@link #addKnownNotation(String)}.
 */
class NotationRegistry constructor(notations: Set<String> = setOf()) {
    private val knownNotations: MutableSet<String>

    init {
        knownNotations = notations.toMutableSet()
    }

    /**
     * Add a known notation name into the registry. This will cause critical notations with that
     * name to no longer invalidate the signature.
     *
     * @param notationName name of the notation
     */
    fun addKnownNotation(notationName: String): NotationRegistry = apply {
        knownNotations.add(notationName)
    }

    /**
     * Return true if the notation name is registered in the registry.
     *
     * @param notationName name of the notation
     * @return true if notation is known, false otherwise.
     */
    fun isKnownNotation(notationName: String): Boolean = knownNotations.contains(notationName)

    /** Clear all known notations from the registry. */
    fun clear() {
        knownNotations.clear()
    }
}
