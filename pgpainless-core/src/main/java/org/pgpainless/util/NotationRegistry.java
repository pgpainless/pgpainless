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

    public NotationRegistry() {

    }

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
