/*
 * Copyright 2020 Paul Schaub.
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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import java.util.TimeZone;

public class TestUtils {

    public static SimpleDateFormat UTC_PARSER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
    static {
        UTC_PARSER.setTimeZone(TimeZone.getTimeZone("UTC"));
    }
    public static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random RANDOM = new Random();

    public static Date getUTCDate(String dateString) {
        try {
            return UTC_PARSER.parse(dateString);
        } catch (ParseException e) {
            return null;
        }
    }

    public static String formatUTCDate(Date date) {
        return UTC_PARSER.format(date);
    }

    public static int getNumberOfItemsInIterator(Iterator<?> iterator) {
        int num = 0;
        while (iterator.hasNext()) {
            iterator.next();
            num++;
        }
        return num;
    }

    public static File createTempDirectory() throws IOException {
        String name = randomString(10);
        File dir = Files.createTempDirectory(name).toFile();
        // dir.deleteOnExit();
        return dir;
    }

    private static String randomString(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }
}
