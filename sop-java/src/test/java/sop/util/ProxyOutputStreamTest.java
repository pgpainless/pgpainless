// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

public class ProxyOutputStreamTest {

    @Test
    public void replaceOutputStreamThrowsNPEForNull() {
        ProxyOutputStream proxy = new ProxyOutputStream();
        assertThrows(NullPointerException.class, () -> proxy.replaceOutputStream(null));
    }

    @Test
    public void testSwappingStreamPreservesWrittenBytes() throws IOException {
        byte[] firstSection = "Foo\nBar\n".getBytes(StandardCharsets.UTF_8);
        byte[] secondSection = "Baz\n".getBytes(StandardCharsets.UTF_8);

        ProxyOutputStream proxy = new ProxyOutputStream();
        proxy.write(firstSection);

        ByteArrayOutputStream swappedStream = new ByteArrayOutputStream();
        proxy.replaceOutputStream(swappedStream);

        proxy.write(secondSection);
        proxy.close();

        assertEquals("Foo\nBar\nBaz\n", swappedStream.toString());
    }
}
