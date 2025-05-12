// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp;

import org.junit.jupiter.api.Test;
import org.pgpainless.key.util.KeyIdUtil;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class LongExtensionTest {

    private final Random random = new Random();

    @Test
    public void testFromOpenPGPKeyId() {
        long id = random.nextLong();
        String hexId = LongExtensionsKt.openPgpKeyId(id);
        assertEquals(16, hexId.length());
        // Calling companion object extension methods from java is tricky.
        // KeyIdUtil delegates to Long.Companion extension method though.
        long parsed = KeyIdUtil.fromLongKeyId(hexId);
        assertEquals(id, parsed, "Long MUST still match after converting to hex and back.");
    }

    @Test
    public void testParsingMalformedHexIdFails() {
        assertThrows(IllegalArgumentException.class, () ->
                        KeyIdUtil.fromLongKeyId("00"),
                "Hex encoding is too short, expect 16 chars.");assertThrows(IllegalArgumentException.class, () ->
                        KeyIdUtil.fromLongKeyId("00010203040506XX"),
                "Hex encoding contains non-hex chars.");
    }
}
