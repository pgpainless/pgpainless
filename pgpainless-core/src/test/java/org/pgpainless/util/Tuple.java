// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

/**
 * Helper class pairing together two values.
 * @param <A> type of the first value
 * @param <B> type of the second value
 * @deprecated Scheduled for removal.
 * TODO: Remove
 */
@Deprecated
public class Tuple<A, B> {

    private final A a;
    private final B b;

    public Tuple(A a, B b) {
        this.a = a;
        this.b = b;
    }

    public A getA() {
        return a;
    }

    public B getB() {
        return b;
    }
}
