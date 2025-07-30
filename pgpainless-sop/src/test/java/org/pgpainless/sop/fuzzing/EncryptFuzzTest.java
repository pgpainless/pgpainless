// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class EncryptFuzzTest {

    private final SOP sop = new SOPImpl();
    private final String password = "sw0rdf1sh";
    private final byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    private static List<byte[]> keys;

    @BeforeAll
    public static void setup() throws IOException {
        keys = getKeys();
    }

    private static List<byte[]> getKeys() throws IOException {
        List<byte[]> keys = new ArrayList<>();

        String dir = "/org/pgpainless/sop/fuzzing/testKeys";
        InputStream in = EncryptFuzzTest.class.getResourceAsStream(dir);
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));

        String file;
        while ((file = reader.readLine()) != null) {
            if (!file.endsWith(".key.asc")) {
                continue;
            }

            try(InputStream fIn = EncryptFuzzTest.class.getResourceAsStream(dir + "/" + file)) {
                byte[] b = Streams.readAll(fIn);
                keys.add(b);
            }
        }
        reader.close();

        return keys;
    }

    @FuzzTest(
            maxDuration = "60s"
    )
    public void decryptFuzzedMessage(FuzzedDataProvider provider) {
        byte[] ciphertext = provider.consumeRemainingAsBytes();
        if (ciphertext.length == 0) {
            return;
        }

        try {
            Decrypt decrypt = sop.decrypt();
            for (byte[] k : keys) {
                decrypt.withKey(k);
            }
            byte[] decrypted = decrypt.withPassword(password)
                    .ciphertext(ciphertext)
                    .toByteArrayAndResult()
                    .getBytes();

            assertArrayEquals(data, decrypted);
        } catch (SOPGPException.BadData e) {
            // expected
        } catch (SOPGPException.CannotDecrypt e) {
            // expected
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
