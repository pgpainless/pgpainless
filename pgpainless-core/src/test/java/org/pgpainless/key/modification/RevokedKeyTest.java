// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class RevokedKeyTest {

    private static final String REVOKED = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xjMEYumXWhYJKwYBBAHaRw8BAQdAsesa7C2dtchG2LDYRPVgNiyXDDltTIW0\n" +
            "7hbPKuklr+LCeAQgFgoACQUCYume7wIdAAAhCRARRbJWkH7x7hYhBCHmM1W/\n" +
            "k8Vt/xDX4xFFslaQfvHusjoBAKeMumYgtr1uwbcNobWhojRjik+Uq7jER1Ph\n" +
            "zrZPPwyaAP9NpV4//AB5BbwUgHMhCErD8L6GZEBOpCWYDgS00eKmCc0kVGVz\n" +
            "dCBVc2VyIDx0ZXN0LnVzZXJAZmxvd2NyeXB0LnRlc3Q+wqcEExYIADgWIQQh\n" +
            "5jNVv5PFbf8Q1+MRRbJWkH7x7gUCYumXWgIbAwULCQgHAgYVCgkICwIEFgID\n" +
            "AQIeAQIXgAAhCRARRbJWkH7x7hYhBCHmM1W/k8Vt/xDX4xFFslaQfvHu0GUB\n" +
            "AJ/FAi0K0YQ/gv9fO2EwSLH9imrXSxtfkzAyCQS32A/IAQDdqUfbABEoQvo2\n" +
            "n1ktpVXroW3XPe3HlYFwSQzpVSHADc44BGLpl1oSCisGAQQBl1UBBQEBB0DJ\n" +
            "8e0hG6v64O4P3qa9n8FxrkNoKS+J+fAW1Vzpf5tBUQMBCAfCjwQYFggAIBYh\n" +
            "BCHmM1W/k8Vt/xDX4xFFslaQfvHuBQJi6ZdaAhsMACEJEBFFslaQfvHuFiEE\n" +
            "IeYzVb+TxW3/ENfjEUWyVpB+8e51yAD/ewAe43L4bXYehVAKq+/CSfXEpYxU\n" +
            "8kZv/mfA6nRfvOIA/iTx2uNw5NzC6TM5ZCBrXVxVGPmR9SwjnBHRmzVAmT8B\n" +
            "=pY9e\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @Test
    public void test() throws IOException {
        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(REVOKED);
        KeyRingInfo info = PGPainless.inspectKeyRing(cert);

        assertFalse(info.isUsableForSigning());
        assertFalse(info.isUsableForEncryption());
    }
}
