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

import java.util.Date;

import sop.util.UTCUtil;

public class DateParser {

    public static final Date BEGINNING_OF_TIME = new Date(0);
    public static final Date END_OF_TIME = new Date(8640000000000000L);

    public static Date parseNotAfter(String notAfter) {
        Date date = notAfter.equals("now") ? new Date() : notAfter.equals("-") ? END_OF_TIME : UTCUtil.parseUTCDate(notAfter);
        if (date == null) {
            Print.errln("Invalid date string supplied as value of --not-after.");
            System.exit(1);
        }
        return date;
    }

    public static Date parseNotBefore(String notBefore) {
        Date date = notBefore.equals("now") ? new Date() : notBefore.equals("-") ? BEGINNING_OF_TIME : UTCUtil.parseUTCDate(notBefore);
        if (date == null) {
            Print.errln("Invalid date string supplied as value of --not-before.");
            System.exit(1);
        }
        return date;
    }
}
