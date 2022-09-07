// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy;

import java.util.HashSet;
import java.util.Set;

/**
 * Registry for known notations.
 * Since signature verification must reject signatures with critical notations that are not known to the application,
 * there must be some way to tell PGPainless which notations actually are known.
 *
 * To add a notation name, call {@link #addKnownNotation(String)}.
 */
public class NotationRegistry {

    private final Set<String> knownNotations = new HashSet<>();

    /**
     * Add a known notation name into the registry.
     * This will cause critical notations with that name to no longer invalidate the signature.
     *
     * @param notationName name of the notation
     */
    public void addKnownNotation(String notationName) {
        if (notationName == null) {
            throw new NullPointerException("Notation name MUST NOT be null.");
        }
        knownNotations.add(notationName);
    }

    /**
     * Return true if the notation name is registered in the registry.
     *
     * @param notationName name of the notation
     * @return true if notation is known, false otherwise.
     */
    public boolean isKnownNotation(String notationName) {
        return knownNotations.contains(notationName);
    }

    /**
     * Clear all known notations from the registry.
     */
    public void clear() {
        knownNotations.clear();
    }
}
