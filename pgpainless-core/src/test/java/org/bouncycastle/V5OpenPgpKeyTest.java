// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.IOException;

public class V5OpenPgpKeyTest {

    // Both key and cert are provided by Daniel on
    //  https://mailarchive.ietf.org/arch/msg/openpgp/Z2Mkq9TfvgY5jUJzlNRwgDsDSUk/
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xVwFY4d/4xYAAAAtCSsGAQQB2kcPAQEHQPlNp7tI1gph5WdwamWH0DMZmbud\n" +
            "iRoIJC6thFQ9+JWjAAD9GXKBexK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditl\n" +
            "sLcOpMKkBR8WCgAAAB8FAmOHf+MDCwkHBRUKDggMAhYAAhsDAh4JBScJAgcC\n" +
            "AAAAIyIhBRe8+DZtlDb3rzfq2hVsZJRlblqXac8tXLNF+Lg0NvZSecUms7MC\n" +
            "rI0Ofp1iKV6QwGFEAQDnd37qxR3r/ezwXEfWUd64NKsHy88o3UG3QasrgR9e\n" +
            "SwEAmCPJHs0LvoU81IFsYhEYaZok9uC0DhdnO2lwYUbCTAXHYQVjh3/jEgAA\n" +
            "ADIKKwYBBAGXVQEFAQEHQPz3/CmqzgFI9D6tvzoPlpHQoyKiQ2JWJ4Dtkl2o\n" +
            "TnFbAwEIBwAA/01gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24Eb3C\n" +
            "jgUYFgoAAAAJBQJjh3/jAhsMAAAAIyIhBRe8+DZtlDb3rzfq2hVsZJRlblqX\n" +
            "ac8tXLNF+Lg0NvZS78S6dZamUg5K+sXfU/N1umwTAP9JjPVrtnHjtvYTazZm\n" +
            "dZhAn8aRLUtGG1owtmLGwCSh6wD/bNrWG4nHfVk/aEHGZ4cjaFlapFr5t1QS\n" +
            "psL7nEy94gs=\n" +
            "=5xrR\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xjcFY4d/4xYAAAAtCSsGAQQB2kcPAQEHQPlNp7tI1gph5WdwamWH0DMZmbud\n" +
            "iRoIJC6thFQ9+JWjwqQFHxYKAAAAHwUCY4d/4wMLCQcFFQoOCAwCFgACGwMC\n" +
            "HgkFJwkCBwIAAAAjIiEFF7z4Nm2UNvevN+raFWxklGVuWpdpzy1cs0X4uDQ2\n" +
            "9lJ5xSazswKsjQ5+nWIpXpDAYUQBAOd3furFHev97PBcR9ZR3rg0qwfLzyjd\n" +
            "QbdBqyuBH15LAQCYI8kezQu+hTzUgWxiERhpmiT24LQOF2c7aXBhRsJMBc48\n" +
            "BWOHf+MSAAAAMgorBgEEAZdVAQUBAQdA/Pf8KarOAUj0Pq2/Og+WkdCjIqJD\n" +
            "YlYngO2SXahOcVsDAQgHwo4FGBYKAAAACQUCY4d/4wIbDAAAACMiIQUXvPg2\n" +
            "bZQ296836toVbGSUZW5al2nPLVyzRfi4NDb2Uu/EunWWplIOSvrF31Pzdbps\n" +
            "EwD/SYz1a7Zx47b2E2s2ZnWYQJ/GkS1LRhtaMLZixsAkoesA/2za1huJx31Z\n" +
            "P2hBxmeHI2hZWqRa+bdUEqbC+5xMveIL\n" +
            "=sVUI\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    @Test
    @Disabled("BC 1.72 does not yet support V5 keys")
    public void testParseCert() throws IOException {
        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(CERT);
    }

    @Test
    @Disabled("BC 1.72 does not yet support V5 keys")
    public void testParseKey() throws IOException {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(KEY);
    }
}
