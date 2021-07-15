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
