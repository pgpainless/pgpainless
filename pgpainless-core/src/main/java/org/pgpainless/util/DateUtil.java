// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public final class DateUtil {

    private DateUtil() {

    }

    // Java's SimpleDateFormat is not thread-safe, therefore we return a new instance on every invocation.
    public static SimpleDateFormat getParser() {
        SimpleDateFormat parser = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        parser.setTimeZone(TimeZone.getTimeZone("UTC"));
        return parser;
    }

    /**
     * Parse a UTC timestamp into a date.
     *
     * @param dateString timestamp
     * @return date
     */
    public static Date parseUTCDate(String dateString) {
        try {
            return getParser().parse(dateString);
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Format a date as UTC timestamp.
     *
     * @param date date
     * @return timestamp
     */
    public static String formatUTCDate(Date date) {
        return getParser().format(date);
    }

    /**
     * Floor a date down to seconds precision.
     * @param date date
     * @return floored date
     */
    public static Date toSecondsPrecision(Date date) {
        long millis = date.getTime();
        long seconds = millis / 1000;
        long floored = seconds * 1000;
        return new Date(floored);
    }

    /**
     * Return the current date "floored" to UTC precision.
     *
     * @return now
     */
    public static Date now() {
        return toSecondsPrecision(new Date());
    }
}
