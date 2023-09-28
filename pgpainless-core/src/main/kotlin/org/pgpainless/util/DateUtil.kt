// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import openpgp.formatUTC
import openpgp.parseUTC
import openpgp.toSecondsPrecision
import java.util.*

class DateUtil {

    companion object {

        /**
         * Parse a UTC timestamp into a date.
         *
         * @param dateString timestamp
         * @return date
         */
        @JvmStatic
        fun parseUTCDate(dateString: String): Date = dateString.parseUTC()

        /**
         * Format a date as UTC timestamp.
         *
         * @param date date
         * @return timestamp
         */
        @JvmStatic
        fun formatUTCDate(date: Date): String = date.formatUTC()

        /**
         * Floor a date down to seconds precision.
         * @param date date
         * @return floored date
         */
        @JvmStatic
        fun toSecondsPrecision(date: Date): Date = date.toSecondsPrecision()

        /**
         * Return the current date "floored" to UTC precision.
         *
         * @return now
         */
        @JvmStatic
        fun now() = toSecondsPrecision(Date())
    }
}