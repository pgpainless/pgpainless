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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Iterator;
import java.util.Random;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.MarkerPacket;

public class TestUtils {

    public static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random RANDOM = new Random();

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
        dir.deleteOnExit();
        return dir;
    }

    private static String randomString(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    public static MarkerPacket getMarkerPacket() throws IOException {
        BCPGInputStream pgpIn = new BCPGInputStream(new ByteArrayInputStream("PGP".getBytes(StandardCharsets.UTF_8)));
        MarkerPacket markerPacket = new MarkerPacket(pgpIn);
        pgpIn.close();
        return markerPacket;
    }
}
