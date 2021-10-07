// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import java.util.Date;

import sop.util.UTCUtil;

public class DateParser {

    public static final Date BEGINNING_OF_TIME = new Date(0);
    public static final Date END_OF_TIME = new Date(8640000000000000L);

    public static Date parseNotAfter(String notAfter) {
        Date date = notAfter.equals("now") ? new Date() : notAfter.equals("-") ? END_OF_TIME : UTCUtil.parseUTCDate(notAfter);
        if (date == null) {
            Print.errln("Invalid date string supplied as value of --not-after.");
            System.exit(1);
        }
        return date;
    }

    public static Date parseNotBefore(String notBefore) {
        Date date = notBefore.equals("now") ? new Date() : notBefore.equals("-") ? BEGINNING_OF_TIME : UTCUtil.parseUTCDate(notBefore);
        if (date == null) {
            Print.errln("Invalid date string supplied as value of --not-before.");
            System.exit(1);
        }
        return date;
    }
}
