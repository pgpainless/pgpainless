// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

/**
 * Backport of java.util.Optional for older Android versions.
 *
 * @param <T> item type
 */
public class Optional<T> {

    private final T item;

    public Optional() {
        this(null);
    }

    public Optional(T item) {
        this.item = item;
    }

    public static <T> Optional<T> of(T item) {
        if (item == null) {
            throw new NullPointerException("Item cannot be null.");
        }
        return new Optional<>(item);
    }

    public static <T> Optional<T> ofNullable(T item) {
        return new Optional<>(item);
    }

    public static <T> Optional<T> ofEmpty() {
        return new Optional<>(null);
    }

    public T get() {
        return item;
    }

    public boolean isPresent() {
        return item != null;
    }

    public boolean isEmpty() {
        return item == null;
    }
}
