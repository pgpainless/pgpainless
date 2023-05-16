// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import javax.annotation.Nonnull;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public final class CollectionUtils {

    private CollectionUtils() {

    }

    /**
     * Return all items returned by the {@link Iterator} as a {@link List}.
     *
     * @param iterator iterator
     * @param <I> type
     * @return list
     */
    @Nonnull
    public static <I> List<I> iteratorToList(@Nonnull Iterator<I> iterator) {
        List<I> items = new ArrayList<>();
        while (iterator.hasNext()) {
            I item = iterator.next();
            items.add(item);
        }
        return items;
    }

    /**
     * Return a new array which contains <pre>t</pre> as first element, followed by the elements of <pre>ts</pre>.
     * @param t head
     * @param ts tail
     * @param <T> type
     * @return t and ts as array
     */
    @Nonnull
    public static <T> T[] concat(@Nonnull T t, @Nonnull T[] ts) {
        T[] concat = (T[]) Array.newInstance(t.getClass(), ts.length + 1);
        concat[0] = t;
        System.arraycopy(ts, 0, concat, 1, ts.length);
        return concat;
    }

    /**
     * Return true, if the given array <pre>ts</pre> contains the element <pre>t</pre>.
     * @param ts elements
     * @param t searched element
     * @param <T> type
     * @return true if ts contains t, false otherwise
     */
    public static <T> boolean contains(@Nonnull T[] ts, @Nonnull T t) {
        for (T i : ts) {
            if (i.equals(t)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add all items from the iterator to the collection.
     *
     * @param <T>        type of item
     * @param iterator   iterator to gather items from
     * @param collection collection to add items to
     */
    public static <T> void addAll(@Nonnull Iterator<T> iterator, @Nonnull Collection<T> collection) {
        while (iterator.hasNext()) {
            collection.add(iterator.next());
        }
    }
}
