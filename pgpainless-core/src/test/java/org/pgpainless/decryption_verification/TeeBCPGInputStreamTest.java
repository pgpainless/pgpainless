// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>, Psalms Christopher Matovu <psalmschristophermatovu@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TeeBCPGInputStreamTest {

    /**
     * This is a regression test for PGPainless silently swallowing the last byte of a message if it was <pre>0xFF</pre>.
     * This was due to a bug caused by a missing masking of the sign-bit during bulk reading from the
     * {@link org.pgpainless.decryption_verification.TeeBCPGInputStream.DelayedTeeInputStream} class.
     *
     * @see <a href="https://github.com/pgpainless/pgpainless/issues/504">Bug Report</a>
     */
    @Test
    public void testDelayedTeeInputStreamDoesNotDropTrailingFF() {
        byte[] input = new byte[] { 0x41, 0x42, (byte) 0xFF };
        InputStream source = new ByteArrayInputStream(input);
        ByteArrayOutputStream teedOutput = new ByteArrayOutputStream();

        TeeBCPGInputStream.DelayedTeeInputStream tee =
                new TeeBCPGInputStream.DelayedTeeInputStream(source, teedOutput);

        byte[] buf = new byte[1024];
        int bytesRead = tee.read(buf, 0, buf.length);
        tee.squeeze();

        byte[] teedBytes = teedOutput.toByteArray();

        // Returns 3 bytes to the caller
        assertEquals(3, bytesRead);
        // But only tees 2 bytes to the output stream (0xFF was dropped)
        assertEquals(3, teedBytes.length, "Expected 3 bytes teed, got " + teedBytes.length);
        // FAILS: expected 3 but got 2
    }
}
