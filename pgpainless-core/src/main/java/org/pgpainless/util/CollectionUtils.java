// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public final class CollectionUtils {

    private CollectionUtils() {

    }

    public static <I> List<I> iteratorToList(Iterator<I> iterator) {
        List<I> items = new ArrayList<>();
        while (iterator.hasNext()) {
            I item = iterator.next();
            items.add(item);
        }
        return items;
    }

    public static <T> T[] concat(T t, T[] ts) {
        T[] concat = (T[]) Array.newInstance(t.getClass(), ts.length + 1);
        concat[0] = t;
        System.arraycopy(ts, 0, concat, 1, ts.length);
        return concat;
    }
}
