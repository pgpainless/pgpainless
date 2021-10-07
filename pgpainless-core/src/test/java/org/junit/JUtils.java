// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.junit;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.pgpainless.util.DateUtil;

public class JUtils {

    public static void assertEquals(long a, long b, long delta) {
        assertTrue(a - delta <= b && a + delta >= b);
    }

    public static void assertDateEquals(Date a, Date b) {
        org.junit.jupiter.api.Assertions.assertEquals(DateUtil.formatUTCDate(a), DateUtil.formatUTCDate(b));
    }
}
