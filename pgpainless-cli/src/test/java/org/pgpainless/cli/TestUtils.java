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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.util.io.Streams;

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

    public static void assertSignatureEquals(String sig1, String sig2) throws IOException {
        assertSignatureEquals(sig1.getBytes(StandardCharsets.UTF_8), sig2.getBytes(StandardCharsets.UTF_8));
    }

    public static void assertSignatureEquals(byte[] sig1, byte[] sig2) throws IOException {
        ByteArrayInputStream sigIn1 = new ByteArrayInputStream(sig1);
        ByteArrayInputStream sigIn2 = new ByteArrayInputStream(sig2);
        assertSignatureEquals(sigIn1, sigIn2);
    }

    public static void assertSignatureEquals(InputStream sig1, InputStream sig2) throws IOException {
        ArmoredInputStream armor1;
        ArmoredInputStream armor2;
        if (sig1 instanceof ArmoredInputStream) {
            armor1 = (ArmoredInputStream) sig1;
        } else {
            armor1 = new ArmoredInputStream(sig1);
        }
        if (sig2 instanceof ArmoredInputStream) {
            armor2 = (ArmoredInputStream) sig2;
        } else {
            armor2 = new ArmoredInputStream(sig2);
        }

        ByteArrayOutputStream bout1 = new ByteArrayOutputStream();
        ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
        Streams.pipeAll(armor1, bout1);
        Streams.pipeAll(armor2, bout2);

        assertArrayEquals(bout1.toByteArray(), bout2.toByteArray());
    }
}
