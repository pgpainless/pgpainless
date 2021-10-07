// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
