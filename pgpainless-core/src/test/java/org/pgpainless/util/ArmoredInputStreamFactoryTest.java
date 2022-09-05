// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    public void testGet_willWrapArmoredInputStreamWithCRC() throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(armored.getBytes());
        ArmoredInputStream plainArmor = new ArmoredInputStream(inputStream);

        ArmoredInputStream armor = ArmoredInputStreamFactory.get(plainArmor);
        assertTrue(armor instanceof CRCingArmoredInputStreamWrapper);
    }

    @Test
    public void testGet_onCRCinArmoredInputStream() throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(armored.getBytes());
        CRCingArmoredInputStreamWrapper crc = new CRCingArmoredInputStreamWrapper(new ArmoredInputStream(inputStream));

        ArmoredInputStream armor = ArmoredInputStreamFactory.get(crc);
        assertSame(crc, armor);
    }
}
