// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.JUtils.assertEquals;

/**
 * Exploratory test for date and time related operations.
 */
public class TimeTest {

    @Test
    public void newDateGetTimeEqualsSystemCurrentTimeMillis() {
        Date date = new Date();
        long dateTime = date.getTime();
        long currentTime = System.currentTimeMillis();

        assertEquals(dateTime, currentTime, 10);
    }
}
