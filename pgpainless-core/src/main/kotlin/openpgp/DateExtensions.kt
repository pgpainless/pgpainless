// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*

/**
 * Return a new date which represents this date plus the given amount of seconds added.
 *
 * Since '0' is a special date value in the OpenPGP specification
 * (e.g. '0' means no expiration for expiration dates), this method will return 'null' if seconds is 0.
 *
 * @param date date
 * @param seconds number of seconds to be added
 * @return date plus seconds or null if seconds is '0'
 */
fun Date.plusSeconds(seconds: Long): Date? {
    require(Long.MAX_VALUE - time > seconds) { "Adding $seconds seconds to this date would cause time to overflow." }
    return if (seconds == 0L) null
    else Date(this.time + 1000 * seconds)
}

/**
 * Return a new [Date] instance with this instance's time floored down to seconds precision.
 */
fun Date.toSecondsPrecision(): Date {
    return Date((time / 1000) * 1000)
}

internal val parser: SimpleDateFormat
    // Java's SimpleDateFormat is not thread-safe, therefore we return a new instance on every invocation.
    get() = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z")
            .apply { timeZone = TimeZone.getTimeZone("UTC") }

/**
 * Format a date as UTC timestamp.
 *
 * @return timestamp
 */
fun Date.formatUTC(): String = parser.format(this)

/**
 * Parse a UTC timestamp into a date.
 * @return date
 */
fun String.parseUTC(): Date {
    return try {
        parser.parse(this)
    } catch (e : ParseException) {
        throw IllegalArgumentException("Malformed UTC timestamp: $this", e)
    }
}
