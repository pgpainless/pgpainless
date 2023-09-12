// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

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
