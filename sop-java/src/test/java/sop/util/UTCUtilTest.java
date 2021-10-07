// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Date;

import org.junit.jupiter.api.Test;

/**
 * Test parsing some date examples from the stateless OpenPGP CLI spec.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-01#section-4.1">OpenPGP Stateless CLI §4.1. Date</a>
 */
public class UTCUtilTest {

    @Test
    public void parseExample1() {
        String timestamp = "2019-10-29T12:11:04+00:00";
        Date date = UTCUtil.parseUTCDate(timestamp);
        assertEquals("2019-10-29T12:11:04Z", UTCUtil.formatUTCDate(date));
    }

    @Test
    public void parseExample2() {
        String timestamp = "2019-10-24T23:48:29Z";
        Date date = UTCUtil.parseUTCDate(timestamp);
        assertEquals("2019-10-24T23:48:29Z", UTCUtil.formatUTCDate(date));
    }

    @Test
    public void parseExample3() {
        String timestamp = "20191029T121104Z";
        Date date = UTCUtil.parseUTCDate(timestamp);
        assertEquals("2019-10-29T12:11:04Z", UTCUtil.formatUTCDate(date));
    }

    @Test
    public void invalidDateReturnsNull() {
        String invalidTimestamp = "foobar";
        Date expectNull = UTCUtil.parseUTCDate(invalidTimestamp);
        assertNull(expectNull);
    }
}
