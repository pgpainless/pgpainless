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
package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;

public class AsciiArmorDashEscapeTest {

    @Test
    public void testDashEscapingInCleartextArmor() throws IOException {
        String withDash = "- This is a leading dash.\n";
        String dashEscaped = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hash: SHA512\n" +
                "\n" +
                "- - This is a leading dash.\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(out);

        armor.beginClearText(HashAlgorithm.SHA512.getAlgorithmId());
        armor.write(withDash.getBytes(StandardCharsets.UTF_8));
        armor.endClearText();
        armor.close();

        assertArrayEquals(dashEscaped.getBytes(StandardCharsets.UTF_8), out.toByteArray());

        ArmoredInputStream armorIn = new ArmoredInputStream(new ByteArrayInputStream(out.toByteArray()));
        ByteArrayOutputStream plain = new ByteArrayOutputStream();
        Streams.pipeAll(armorIn, plain);
        assertEquals(withDash, plain.toString());
    }
}
