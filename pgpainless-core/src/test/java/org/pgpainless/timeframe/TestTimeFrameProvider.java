// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.timeframe;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class TestTimeFrameProvider {

    /**
     * Return an expiration date which is 7h 13m and 31s from the given date.
     *
     * @param now t0
     * @return t1 which is t0 +7h13m31s
     */
    public static Date defaultExpirationForCreationDate(Date now) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.setTime(now);
        calendar.add(Calendar.HOUR, 7);
        calendar.add(Calendar.MINUTE, 13);
        calendar.add(Calendar.SECOND, 31);
        return calendar.getTime();
    }
}
