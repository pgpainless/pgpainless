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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Utility class of an immutable list which cannot be empty.
 * The first element can be accessed via {@link #get()} which is guaranteed to return a non-null value.
 * The rest of the list can be accessed via {@link #getOthers()}, which is guaranteed to return a non-null list which is possibly empty.
 * Lastly, the whole list can be accessed via {@link #getAll()}, which is guaranteed to return a non-empty list.
 *
 * @param <E> element type
 */
public class NonEmptyList<E> {

    private final List<E> elements;

    /**
     * Create a singleton list from the given element.
     *
     * @param element element
     */
    public NonEmptyList(E element) {
        if (element == null) {
            throw new IllegalArgumentException("Singleton element cannot be null.");
        }
        this.elements = Collections.singletonList(element);
    }

    /**
     * Create a non-empty list from the given list of elements.
     *
     * @param elements elements
     * @throws IllegalArgumentException if the provided list of elements is empty.
     */
    public NonEmptyList(List<E> elements) {
        if (elements.isEmpty()) {
            throw new IllegalArgumentException("Underlying list cannot be empty.");
        }
        this.elements = Collections.unmodifiableList(elements);
    }

    /**
     * Return the first element of the list.
     *
     * @return first
     */
    public @Nonnull E get() {
        return elements.get(0);
    }

    /**
     * Return a list of all elements of the list except the first.
     *
     * @return list of all but the first element
     */
    public @Nonnull List<E> getOthers() {
        List<E> others = new LinkedList<>(elements);
        others.remove(0);
        return Collections.unmodifiableList(others);
    }

    /**
     * Return a non-empty list of all elements of this list.
     *
     * @return all elements
     */
    public List<E> getAll() {
        return elements;
    }
}
