// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KeyWithUnsupportedSignatureSubpacketTest {

    @Test
    public void testCanSetExpirationDateOnKeyContainingUnknownSubpacket34() throws IOException, PGPException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lFgEZWiyNhYJKwYBBAHaRw8BAQdA71QipJ0CAqOEqQWjuoQE4E7LarKSrNDwE/6K\n" +
                "bQNrCLwAAQCtJ8kVG2AmbDfdVtr/7Ag+yBh0oCvjRvyUCOyIbruOeg+6tClTdWJw\n" +
                "YWNrZXQzNCBUZXN0S2V5IDx0ZXN0QHBncGFpbmxlc3Mub3JnPoiTBBMWCgA7FiEE\n" +
                "zhy5yrnZYU/iBza4G03SQVuWqx0FAmVosjYCGwMFCwkIBwICIgIGFQoJCAsCBBYC\n" +
                "AwECHgcCF4AACgkQG03SQVuWqx1UGgD+IYLeh9t5eJCEnzueuOTYnTnrzyhnLgm9\n" +
                "dw5qwMXU8VQA/28GCOb7610hyjiBbrrcshkWAKuMwp8bUSz5FOeS5cQEnF0EZWiy\n" +
                "NhIKKwYBBAGXVQEFAQEHQK99ClLDYtn0I2b6Y26NhaL0RWcrNoI/ci0xgXEK2L0Y\n" +
                "AwEIBwAA/06qciQHI0v7MP2LMWm/ZuTJwzlPqV8VsBhrDMyUPUD4D52IeAQYFgoA\n" +
                "IBYhBM4cucq52WFP4gc2uBtN0kFblqsdBQJlaLI2AhsMAAoJEBtN0kFblqsdRQ0A\n" +
                "/iUJ/Fp+D2RjZL+aiwByIxPCVvMJ7a28+GQGjg3hsU2BAP474dfOOVZiTDLWWxsB\n" +
                "wxfzOAQxXDhgR9xd/Lk3MNJxDg==\n" +
                "=YAt0\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        assertNotNull(secretKeys);
        PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(), SecretKeyRingProtector.unprotectedKeys())
                .done();
    }
}
