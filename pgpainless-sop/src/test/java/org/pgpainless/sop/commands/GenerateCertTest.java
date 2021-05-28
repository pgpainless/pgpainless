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
package org.pgpainless.sop.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.pgpainless.sop.TestUtils.ARMOR_PRIVATE_KEY_HEADER_BYTES;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Arrays;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.sop.PGPainlessCLI;
import org.pgpainless.sop.TestUtils;
import picocli.CommandLine;

public class GenerateCertTest {

    private static File tempDir;


    @BeforeAll
    public static void setup() throws IOException {
        tempDir = TestUtils.createTempDirectory();
    }

    @Test
    public void testKeyGeneration() throws IOException, PGPException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        new CommandLine(new PGPainlessCLI()).execute("generate-key", "--armor", "Juliet Capulet <juliet@capulet.lit>");

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(out.toByteArray());
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("Juliet Capulet <juliet@capulet.lit>"));

        byte[] outBegin = new byte[37];
        System.arraycopy(out.toByteArray(), 0, outBegin, 0, 37);
        assertArrayEquals(outBegin, ARMOR_PRIVATE_KEY_HEADER_BYTES);
    }

    @Test
    public void testNoArmor() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        new CommandLine(new PGPainlessCLI()).execute("generate-key", "--no-armor", "Test <test@test.test>");

        byte[] outBegin = new byte[37];
        System.arraycopy(out.toByteArray(), 0, outBegin, 0, 37);
        assertFalse(Arrays.equals(outBegin, ARMOR_PRIVATE_KEY_HEADER_BYTES));
    }
}
