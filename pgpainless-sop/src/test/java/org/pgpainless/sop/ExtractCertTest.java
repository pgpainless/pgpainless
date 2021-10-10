// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sop.SOP;
import sop.exception.SOPGPException;

public class ExtractCertTest {

    public static final String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A8D9 9FF4 C8DD BBA6 C610  A6B7 9ACB 2195 A9BC DF5B\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEYSzwMhYJKwYBBAHaRw8BAQdA60pbfTLh5MB1Ka5KfZqUzMhHzJHYBvXF68mW\n" +
            "BMzgupIAAPsHWal9lDZzNXUE8Xnt00IUFYhOC5P73FMLGqdpsA+fQw51tBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iHgEExYKACAFAmEs8DICGwEFFgIDAQAE\n" +
            "CwkIBwUVCgkICwIeAQIZAQAKCRCayyGVqbzfW9EWAQDQbiKUpftQsK4IXJJ1d40H\n" +
            "fe7Djhm0P08Oo73GeE8vLwEA0ArOcyBbOETBBIefigVWWay6JIt57DGxR6KWQABk\n" +
            "AwKcXQRhLPAyEgorBgEEAZdVAQUBAQdAa3lioBiWVujoFINa2wVNPLjf/hc1aIPK\n" +
            "sbAcs83uRysDAQgHAAD/QJGlp9SjIzT9o2e+x9jyndOhyMPSmlLljW9ZtSuzmrgU\n" +
            "uYh1BBgWCgAdBQJhLPAyAhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQmsshlam8\n" +
            "31u3awEA0b/hCRQNrtsITuQGS1ikzonhJITpbmrg/ZVOvBn+3jYBAIC5d4Hozn1O\n" +
            "aBBl1ZiY3Bl2qIFYWzVR9vFOm+Va3lkEnFgEYSzwMhYJKwYBBAHaRw8BAQdAFfJi\n" +
            "f64K8E2ZlBqAAxO0eG7nIlxRYlOvbN/1vP8grW8AAP0cKOpo2uFqLzTnmzJ+rpmV\n" +
            "gwUW1FiHGpM/awfg+zzCgBAxiNUEGBYKAH0FAmEs8DICGwIFFgIDAQAECwkIBwUV\n" +
            "CgkICwIeAV8gBBkWCgAGBQJhLPAyAAoJEOVqq3ZdDwXc3WAA/2UaO79+srF3p/f9\n" +
            "scsmj7Rax8uXKw8sJPdgPMjmo404AQDor96bTeBiGOwPq0UfY4GGRmdkH8Z95PE+\n" +
            "fKyEbkjFAgAKCRCayyGVqbzfWwmUAP9AtTcZZPHa/gMYr5KXI+L7VRie9iolKII7\n" +
            "glyfG0/RUwEA3hTvAPRPAFG5WFNYaQprBAnAsefmdqwdDJGPfR7uGg0=\n" +
            "=BVSY\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    public static final String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A8D9 9FF4 C8DD BBA6 C610  A6B7 9ACB 2195 A9BC DF5B\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "mDMEYSzwMhYJKwYBBAHaRw8BAQdA60pbfTLh5MB1Ka5KfZqUzMhHzJHYBvXF68mW\n" +
            "BMzgupK0HEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz6IeAQTFgoAIAUCYSzw\n" +
            "MgIbAQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJEJrLIZWpvN9b0RYBANBuIpSl\n" +
            "+1CwrghcknV3jQd97sOOGbQ/Tw6jvcZ4Ty8vAQDQCs5zIFs4RMEEh5+KBVZZrLok\n" +
            "i3nsMbFHopZAAGQDArg4BGEs8DISCisGAQQBl1UBBQEBB0BreWKgGJZW6OgUg1rb\n" +
            "BU08uN/+FzVog8qxsByzze5HKwMBCAeIdQQYFgoAHQUCYSzwMgIbDAUWAgMBAAQL\n" +
            "CQgHBRUKCQgLAh4BAAoJEJrLIZWpvN9bt2sBANG/4QkUDa7bCE7kBktYpM6J4SSE\n" +
            "6W5q4P2VTrwZ/t42AQCAuXeB6M59TmgQZdWYmNwZdqiBWFs1UfbxTpvlWt5ZBLgz\n" +
            "BGEs8DIWCSsGAQQB2kcPAQEHQBXyYn+uCvBNmZQagAMTtHhu5yJcUWJTr2zf9bz/\n" +
            "IK1viNUEGBYKAH0FAmEs8DICGwIFFgIDAQAECwkIBwUVCgkICwIeAV8gBBkWCgAG\n" +
            "BQJhLPAyAAoJEOVqq3ZdDwXc3WAA/2UaO79+srF3p/f9scsmj7Rax8uXKw8sJPdg\n" +
            "PMjmo404AQDor96bTeBiGOwPq0UfY4GGRmdkH8Z95PE+fKyEbkjFAgAKCRCayyGV\n" +
            "qbzfWwmUAP9AtTcZZPHa/gMYr5KXI+L7VRie9iolKII7glyfG0/RUwEA3hTvAPRP\n" +
            "AFG5WFNYaQprBAnAsefmdqwdDJGPfR7uGg0=\n" +
            "=9qam\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static SOP sop;

    @BeforeAll
    public static void setup() {
        sop = new SOPImpl();
    }

    @Test
    public void basicExtractCert() throws IOException {
        assertArrayEquals(
                cert.getBytes(StandardCharsets.UTF_8),
                sop.extractCert()
                        .key(key.getBytes(StandardCharsets.UTF_8))
                        .getBytes());
    }

    @Test
    public void emptyKeyDataYieldsBadData() {
        assertThrows(SOPGPException.BadData.class, () -> sop.extractCert()
                .key(new byte[0]));
    }
}
