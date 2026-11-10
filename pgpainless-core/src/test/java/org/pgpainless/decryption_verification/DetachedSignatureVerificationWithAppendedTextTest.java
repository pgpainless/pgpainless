// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DetachedSignatureVerificationWithAppendedTextTest {

    @Test
    public void test() throws IOException, PGPException {
        String plaintext = "Hello, World!\n";
        String armoredLit = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.86\n" +
                "\n" +
                "yxRiAAAAAABIZWxsbywgV29ybGQhCg==\n" +
                "=WGju\n" +
                "-----END PGP MESSAGE-----\n";
        String keyArmor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 4B54 552C 275E 0BAD A5CB  4398 994F 84EB A718 75E3\n" +
                "Comment: Alice <alice@example.org>\n" +
                "\n" +
                "lFgEavOJihYJKwYBBAHaRw8BAQdAIgLj68SghmYh/b36oVLM43cMwCQwPF8hF3gR\n" +
                "hWqg53kAAQDvtOrFCfbRuYNnF5QlQwu6Mgkmc/3yL+A9ATGqbWRvNw8AwpwEHxYK\n" +
                "AE4JEJlPhOunGHXjFqEES1RVLCdeC62ly0OYmU+E66cYdeMFgmrziYoCmwEFFQoJ\n" +
                "CAsFFgIDAQAECwkIBwknCQEJAgkDCAECngkFiQlmAYAAALJaAPwKSTTWk5w+FSxh\n" +
                "HUGy/nhcoeuPH6Fpcg3MpwFUMzDVEgD+NSgegwtrmpcNEfgwegCrsNkgkgUwkXP8\n" +
                "49g22zDlWAm0GUFsaWNlIDxhbGljZUBleGFtcGxlLm9yZz7CnwQTFgoAUQkQmU+E\n" +
                "66cYdeMWoQRLVFUsJ14LraXLQ5iZT4Trpxh14wWCavOJigKbAQUVCgkICwUWAgMB\n" +
                "AAQLCQgHCScJAQkCCQMIAQKeCQWJCWYBgAKZAQAA9h8A/AvXVp7hkn3PMjyweJdA\n" +
                "fpvVDkKqTxIw1dj7Qc12Qm+5AP44wjsKGYFbOQBJO+LPaJbqeswNMDewTuo8iubV\n" +
                "ZETYBpxdBGrziYoSCisGAQQBl1UBBQEBB0AK8hTrv4e65csmpeNUgGmcL9M50rQh\n" +
                "TamzsHOdnZ4VOgMBCAcAAP95JEjGaBEDpNIbh3Jpw0rMN6X+3fSEHv5ELPtz47fQ\n" +
                "QBHFwngEGBYKACoJEJlPhOunGHXjFqEES1RVLCdeC62ly0OYmU+E66cYdeMFgmrz\n" +
                "iYoCmwwAAEkqAQDkmN4eUG+K2XVn7ppQCzvgBhbk09WKzIllaKa81qQP3gD9FQEE\n" +
                "W636mnqFVbRoQBHm7SntJyMuDmN18cbnaP38uwqcWARq84mKFgkrBgEEAdpHDwEB\n" +
                "B0AgONTGA4/vWcfOE6Z0qDVrtMIFOYP4rrkmW6o0uDsxpgABAOIbJyUxMEy3HnNE\n" +
                "NbyjfcdGOaG+zvxTnCEi3IyvVcloDtLCwC8EGBYKAKEJEJlPhOunGHXjFqEES1RV\n" +
                "LCdeC62ly0OYmU+E66cYdeMFgmrziYoCmwJ2IAQZFgoAHQWCavOJihYhBKWTcL15\n" +
                "j81+sd5UCpb7MWKu/fs/AAoJEJb7MWKu/fs/gZUBANMX5TjeTOXXBwYQBAF6BPfZ\n" +
                "Ni8Nia3UWnMkVd5wc3EcAP4iEI7NFFFjvYZgTLaPEusngOtWeKhWZz/gE1fGyI+f\n" +
                "AgAAw08A/0LvUpnZqo1uY9iOX/s0AWjtSUoxHS2PebUaJhapaF3tAP91SyWqwmbL\n" +
                "hmoNrrOCrxds9ziZGb0HaTD8mz9MhoK5CQ==\n" +
                "=Jb3K\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        String detachedSig = "-----BEGIN PGP SIGNATURE-----\n" +
                "Comment: A593 70BD 798F CD7E B1DE  540A 96FB 3162 AEFD FB3F\n" +
                "\n" +
                "wnUEABYKACcFgmrzikYJEJb7MWKu/fs/FqEEpZNwvXmPzX6x3lQKlvsxYq79+z8A\n" +
                "AMwWAQCbvPUSDSXmRaqSYxjF6HsG0X5aCtpNneefphswOjmDbAEAipgUgW55j7OO\n" +
                "aSCYObBYB2ab1qtSQZgwuIpKM0xIKwk=\n" +
                "=QQzV\n" +
                "-----END PGP SIGNATURE-----";

        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.readKey().parseKey(keyArmor);
        String litWithAppendedData = armoredLit + "\nHeyho let's go!\n";

        PGPSignature sig = api.readSignatures().fromArmor(detachedSig).get(0);
        DecryptionStream dIn = api.processMessage()
                .onInputStream(new ByteArrayInputStream(litWithAppendedData.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get(api)
                        .addVerificationCert(key)
                        .addVerificationOfDetachedSignature(sig));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(dIn, bOut);
        dIn.close();

        assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), bOut.toByteArray());
        assertTrue(dIn.getMetadata().isVerifiedSigned());
    }
}
