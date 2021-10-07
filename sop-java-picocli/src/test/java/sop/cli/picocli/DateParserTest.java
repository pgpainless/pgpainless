// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.Test;
import sop.util.UTCUtil;

public class DateParserTest {

    @Test
    public void parseNotAfterDashReturnsEndOfTime() {
        assertEquals(DateParser.END_OF_TIME, DateParser.parseNotAfter("-"));
    }

    @Test
    public void parseNotBeforeDashReturnsBeginningOfTime() {
        assertEquals(DateParser.BEGINNING_OF_TIME, DateParser.parseNotBefore("-"));
    }

    @Test
    public void parseNotAfterNowReturnsNow() {
        assertEquals(new Date().getTime(), DateParser.parseNotAfter("now").getTime(), 1000);
    }

    @Test
    public void parseNotBeforeNowReturnsNow() {
        assertEquals(new Date().getTime(), DateParser.parseNotBefore("now").getTime(), 1000);
    }

    @Test
    public void parseNotAfterTimestamp() {
        String timestamp = "2019-10-24T23:48:29Z";
        Date date = DateParser.parseNotAfter(timestamp);
        assertEquals(timestamp, UTCUtil.formatUTCDate(date));
    }

    @Test
    public void parseNotBeforeTimestamp() {
        String timestamp = "2019-10-29T18:36:45Z";
        Date date = DateParser.parseNotBefore(timestamp);
        assertEquals(timestamp, UTCUtil.formatUTCDate(date));
    }
}
