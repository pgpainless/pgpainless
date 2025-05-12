// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DateExtensionTest {

    @Test
    public void testDatePlusSecondsBaseCase() {
        Date t0 = DateExtensionsKt.parseUTC("2025-05-12 10:36:53 UTC");
        Date t1 = DateExtensionsKt.plusSeconds(t0, 7);
        assertEquals("2025-05-12 10:37:00 UTC", DateExtensionsKt.formatUTC(t1));
    }

    @Test
    public void testDatePlusZeroReturnsNull() {
        Date t0 = DateExtensionsKt.parseUTC("2025-05-12 10:36:53 UTC");
        Date t1 = DateExtensionsKt.plusSeconds(t0, 0);
        assertNull(t1);
    }

    @Test
    public void testDatePlusSecondsOverflowing() {
        Date now = new Date();
        // expect IAE because of time field overflowing
        assertThrows(IllegalArgumentException.class, () ->
                DateExtensionsKt.plusSeconds(now, Long.MAX_VALUE - 10000));
    }

    @Test
    public void testParsingMalformedUTCTimestampThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                DateExtensionsKt.parseUTC("2025-05-12 10:36:XX UTC"));
    }
}
