/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class DateUtil {

    public static SimpleDateFormat UTC_PARSER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
    static {
        UTC_PARSER.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    /**
     * Parse a UTC timestamp into a date.
     *
     * @param dateString timestamp
     * @return date
     */
    public static Date parseUTCDate(String dateString) {
        try {
            return UTC_PARSER.parse(dateString);
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
        return UTC_PARSER.format(date);
    }

    /**
     * Return the current date "rounded" to UTC precision.
     *
     * @return now
     */
    public static Date now() {
        return parseUTCDate(formatUTCDate(new Date()));
    }
}
