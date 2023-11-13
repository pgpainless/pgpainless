// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ArmoredInputStreamFactoryTest {

    // Hello World!\n
    String armored = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "owE7LZzEAAIeqTk5+Qrh+UU5KYpcAA==\n" +
            "=g3nV\n" +
            "-----END PGP MESSAGE-----";

    @Test
    public void testGet() throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(armored.getBytes());
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(inputStream);
        assertNotNull(armorIn);
    }
}
