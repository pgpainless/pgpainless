// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;

import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;

public class TestUtils {


    public static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random RANDOM = new Random();

    public static final String ARMOR_PRIVATE_KEY_HEADER = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    public static final byte[] ARMOR_PRIVATE_KEY_HEADER_BYTES =
            ARMOR_PRIVATE_KEY_HEADER.getBytes(StandardCharsets.UTF_8);
    public static final String ARMOR_SIGNATURE_HEADER = "-----BEGIN PGP SIGNATURE-----";
    public static final byte[] ARMOR_SIGNATURE_HEADER_BYTES =
            ARMOR_SIGNATURE_HEADER.getBytes(StandardCharsets.UTF_8);

    public static File createTempDirectory() throws IOException {
        String name = randomString(10);
        File dir = Files.createTempDirectory(name).toFile();
        // dir.deleteOnExit();
        return dir;
    }

    public static File writeTempFile(File tempDir, byte[] value) throws IOException {
        File tempFile = new File(tempDir, randomString(10));
        tempFile.createNewFile();
        tempFile.deleteOnExit();
        FileOutputStream fileOutputStream = new FileOutputStream(tempFile);
        fileOutputStream.write(value);
        fileOutputStream.flush();
        fileOutputStream.close();
        return tempFile;
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
        InputStream sigIn1 = PGPUtil.getDecoderStream(new ByteArrayInputStream(sig1));
        InputStream sigIn2 = PGPUtil.getDecoderStream(new ByteArrayInputStream(sig2));
        assertSignatureEquals(sigIn1, sigIn2);
    }

    public static void assertSignatureEquals(InputStream sig1, InputStream sig2) throws IOException {

        ByteArrayOutputStream bout1 = new ByteArrayOutputStream();
        ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
        Streams.pipeAll(sig1, bout1);
        Streams.pipeAll(sig2, bout2);

        assertArrayEquals(bout1.toByteArray(), bout2.toByteArray());
    }

    public static void assertSignatureIsArmored(byte[] sig) {
        assertTrue(isSignatureArmored(sig), "Signature encoding does not start with armor header.\n" +
                "Expected: " + ARMOR_SIGNATURE_HEADER + "\n" +
                "Actual: " + new String(sig));
    }

    public static void assertSignatureIsNotArmored(byte[] sig) {
        assertFalse(isSignatureArmored(sig), "Signature encoding starts with armor header.\n" +
                "Actual: " + new String(sig));
    }

    public static boolean isSignatureArmored(byte[] sig) {
        boolean same = true;
        for (int i = 0; i < ARMOR_SIGNATURE_HEADER_BYTES.length; i++) {
            if (sig[i] != ARMOR_SIGNATURE_HEADER_BYTES[i]) {
                same = false;
                break;
            }
        }
        return same;
    }
}
