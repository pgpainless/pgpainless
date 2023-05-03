// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import javax.annotation.Nonnull;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public final class DateUtil {

    private DateUtil() {

    }

    // Java's SimpleDateFormat is not thread-safe, therefore we return a new instance on every invocation.
    @Nonnull
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
    @Nonnull
    public static Date parseUTCDate(@Nonnull String dateString) {
        try {
            return getParser().parse(dateString);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Malformed UTC timestamp: " + dateString, e);
        }
    }

    /**
     * Format a date as UTC timestamp.
     *
     * @param date date
     * @return timestamp
     */
    @Nonnull
    public static String formatUTCDate(Date date) {
        return getParser().format(date);
    }

    /**
     * Floor a date down to seconds precision.
     * @param date date
     * @return floored date
     */
    @Nonnull
    public static Date toSecondsPrecision(@Nonnull Date date) {
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
    @Nonnull
    public static Date now() {
        return toSecondsPrecision(new Date());
    }
}
