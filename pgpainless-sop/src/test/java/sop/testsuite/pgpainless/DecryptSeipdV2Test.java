// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.sop.SOPImpl;
import sop.ByteArrayAndResult;
import sop.SOP;
import sop.Verification;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class DecryptSeipdV2Test {

    @Test
    public void testDecryptionOfPKESK6SEIPD2Message() throws IOException, PGPException {
        // Test message generated using sq
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmIA5PducqZ21f5\n" +
                "YQVwrKzMnclNp2qQMk94NIFRydzgQij/XnCVsh2KiZ2KAqAaDzRAzCC44X2zcEYa\n" +
                "hDlDitRJDyIy+WqJnlSw0loCCQIGMUNKfc/Fx6J4968MksBh5w7HmCamhqE6exup\n" +
                "bnHBi/kGB8rz2RGCJpH06zRVBYBl/voL/frzdvttIETbPp+Dwru+exD/MyrWpS6r\n" +
                "PuJNzr6MLp9ukHk=\n" +
                "=Eisa\n" +
                "-----END PGP MESSAGE-----\n";
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        PGPSecretKeyRing k = PGPainless.readKeyRing().secretKeyRing(key);
        DecryptionStream d = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get().addDecryptionKey(k));
        Streams.drain(d);
        d.close();
    }

    @Test
    public void inlineSignVerifyTest() throws IOException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        SOP sop = new SOPImpl();
        byte[] signed = sop.inlineSign()
                .key(KEY.getBytes(StandardCharsets.UTF_8))
                .data("Hello".getBytes(StandardCharsets.UTF_8))
                .getBytes();

        byte[] cert = sop.extractCert()
                .noArmor()
                .key(KEY.getBytes(StandardCharsets.UTF_8))
                .getBytes();

        ByteArrayAndResult<List<Verification>> result = sop.inlineVerify()
                .cert(cert)
                .data(signed)
                .toByteArrayAndResult();

        assertFalse(result.getResult().isEmpty());
    }
}
