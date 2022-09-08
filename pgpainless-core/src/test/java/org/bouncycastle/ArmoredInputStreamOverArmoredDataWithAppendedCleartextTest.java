// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ArmoredInputStreamOverArmoredDataWithAppendedCleartextTest {

    private static final String ASCII_ARMORED_WITH_APPENDED_GARBAGE = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "yxRiAAAAAABIZWxsbywgV29ybGQhCg==\n" +
            "=WGju\n" +
            "-----END PGP MESSAGE-----\n" +
            "This is a bunch of crap that we appended.";
    @Test
    public void testArmoredInputStreamCutsOffAnyDataAfterTheAsciiArmor() throws IOException {
        InputStream inputStream = new ByteArrayInputStream(ASCII_ARMORED_WITH_APPENDED_GARBAGE.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(inputStream);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(armorIn, out);
        armorIn.close();

        assertEquals(22, out.size(), "ArmoredInputStream cuts off any appended data outside the ASCII armor.");
    }
}
