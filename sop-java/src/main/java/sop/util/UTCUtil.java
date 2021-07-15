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
package sop.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Utility class to parse and format dates as ISO-8601 UTC timestamps.
 */
public class UTCUtil {

    public static SimpleDateFormat UTC_FORMATTER = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    public static SimpleDateFormat[] UTC_PARSERS = new SimpleDateFormat[] {
            UTC_FORMATTER,
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX"),
            new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'"),
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'")
    };

    static {
        for (SimpleDateFormat f : UTC_PARSERS) {
            f.setTimeZone(TimeZone.getTimeZone("UTC"));
        }
    }
    /**
     * Parse an ISO-8601 UTC timestamp from a string.
     *
     * @param dateString string
     * @return date
     */
    public static Date parseUTCDate(String dateString) {
        for (SimpleDateFormat parser : UTC_PARSERS) {
            try {
                return parser.parse(dateString);
            } catch (ParseException e) {
            }
        }
        return null;
    }

    /**
     * Format a date as ISO-8601 UTC timestamp.
     *
     * @param date date
     * @return timestamp string
     */
    public static String formatUTCDate(Date date) {
        return UTC_FORMATTER.format(date);
    }
}
