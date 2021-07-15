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
