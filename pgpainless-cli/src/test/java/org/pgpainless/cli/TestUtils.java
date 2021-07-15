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
package org.pgpainless.cli;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;

public class TestUtils {

    public static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random RANDOM = new Random();

    public static final String ARMOR_PRIVATE_KEY_HEADER = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    public static final byte[] ARMOR_PRIVATE_KEY_HEADER_BYTES =
            ARMOR_PRIVATE_KEY_HEADER.getBytes(StandardCharsets.UTF_8);

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
