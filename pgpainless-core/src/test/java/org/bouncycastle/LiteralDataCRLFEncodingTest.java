// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPCanonicalizedDataGenerator;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;

public class LiteralDataCRLFEncodingTest {

    @Test
    public void testCanonicalization() throws IOException {
        PGPCanonicalizedDataGenerator generator = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OutputStream canonicalizer = generator.open(out, PGPCanonicalizedDataGenerator.UTF8, "", new Date(), new byte[1<<9]);

        ByteArrayInputStream in = new ByteArrayInputStream("Foo\nBar\n".getBytes(StandardCharsets.UTF_8));
        Streams.pipeAll(in, canonicalizer);
        canonicalizer.close();

        byte[] bytes = out.toByteArray();
        byte[] canonicalized = new byte[bytes.length - 8]; // header is not interesting
        System.arraycopy(bytes, 8, canonicalized, 0, canonicalized.length);
        assertArrayEquals(new byte[] {
                // F o o \r \n B a r \r \n
                70, 111, 111, 13, 10, 66, 97, 114, 13, 10},
                canonicalized);
    }
}
