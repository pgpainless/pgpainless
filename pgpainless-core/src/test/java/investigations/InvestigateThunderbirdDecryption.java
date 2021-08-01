/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package investigations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;

public class InvestigateThunderbirdDecryption {

    String OUR_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 47D2 3A5E 1455 1FD2 0599  C1FC B57B 5451 9E2D 8FE4\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEYP8FlBYJKwYBBAHaRw8BAQdAeJ7fL4TbpSLUJsxGUFnN5MzDZr3lKoKWEO+z\n" +
            "hQEFPqcAAP0T8ED8kcch++7UpcN7qZMP4ihbE9Fu9kp/IKOCZDVwGhF+tBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iHgEExYKACAFAmD/BZQCGwEFFgIDAQAE\n" +
            "CwkIBwUVCgkICwIeAQIZAQAKCRC1e1RRni2P5PYqAQC/r4R4RFfVIOPAc16PiffO\n" +
            "GDMzRUYAjIyflvOBIEE//QEAsZGQzIstdIp8gY5CF27pbnnSAA/OGPXbDsNArzPN\n" +
            "tQicXQRg/wWUEgorBgEEAZdVAQUBAQdAFHEP5NzgON0usvHOsTsROojwVTAqgayc\n" +
            "fdPdb597u3UDAQgHAAD/ShtbTmAyZJDjcEDfUNblOogyWntCEgb18Cs5rRm1+agP\n" +
            "mIh1BBgWCgAdBQJg/wWUAhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQtXtUUZ4t\n" +
            "j+SWdwD/cCXm/ufcaIMMOqRw10Lwefc4euOrpFScWA0rUjnK6yEBAMOH1kGHlLbz\n" +
            "mk6D7RbBDdC3aW4xGRjSYBkyhbuxevsDnFgEYP8FlBYJKwYBBAHaRw8BAQdAmuvN\n" +
            "FF+pklSxw3+VVqVu2g2ulpJE7HldtU/Jud/jiEgAAP0RPh7QWqm2hhY6vBNr8fhz\n" +
            "3GBAfZ4A9HxVymuu1M6qMxEdiNUEGBYKAH0FAmD/BZQCGwIFFgIDAQAECwkIBwUV\n" +
            "CgkICwIeAV8gBBkWCgAGBQJg/wWUAAoJEIYvdZaRbR0mBesA/2dxyf9vfRnyrNcm\n" +
            "dguMzYe9oLfD2SU2Sa0jXcURQ+A6AP9uYaehPZvEH0kwdeSi60uCOVznCePrY1mK\n" +
            "M6UEDMPGBwAKCRC1e1RRni2P5J1FAQDhI3tN5C/klh2j8ptQ7ht0LPlbgVU/WmT8\n" +
            "kqejd80WVgEA4dg7MZTk+uzwOWEGIHyxWXRzma9a5k1kM+uxX3RflQU=\n" +
            "=IEzi\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    String THEIR_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: FlowCrypt [BUILD_REPLACEABLE_VERSION] Gmail Encryption\n" +
            "Comment: Seamlessly send and receive encrypted email\n" +
            "\n" +
            "xjMEYL/CRRYJKwYBBAHaRw8BAQdAxaJrnD/gWRGqaAVtQ8R9PI0ZGu/YESJ4\n" +
            "HsJeeCxUZOvNF0RlbiA8ZGVuQGZsb3djcnlwdC5jb20+wn4EExYKACYFAmC/\n" +
            "wkUCGwMFFgIDAQAECwkIBwUVCgkICwIeAQIZAQWJAQ/XOQAKCRCGwF2G4DXc\n" +
            "cttHAP9Axna+jmFhZEajILW7BZ8UJpgz7mCC48RMtRj/pre4nQD/bKJXB+sD\n" +
            "zti+tRbi7KNncgkSQeau+Vy/ZnpBUUHBWwjOOARgv8JFEgorBgEEAZdVAQUB\n" +
            "AQdA3dN8Hh18Pqd6OevXWl36y7cM58ZRmUVEEZukXRIholYDAQgHwnUEGBYK\n" +
            "AB0FAmC/wkUCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRCGwF2G4DXcclpK\n" +
            "AQC0uUHWUFNao1Fl85+4c8WecGKsGCihNU9H3q+I1gz22gEAtVo1dWnc0t1f\n" +
            "h1MUYq5FmME+KeFCBZZ9lrMAxRhvigI=\n" +
            "=+XVJ\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    @Test
    public void generateMessage() throws PGPException, IOException {
        // CHECKSTYLE:OFF
        System.out.println("Decryption Key");
        System.out.println(OUR_KEY);
        // CHECKSTYLE:ON

        PGPSecretKeyRing ourKey = PGPainless.readKeyRing().secretKeyRing(OUR_KEY);
        PGPPublicKeyRing ourCert = PGPainless.extractCertificate(ourKey);
        PGPPublicKeyRing theirCert = PGPainless.readKeyRing().publicKeyRing(THEIR_CERT);

        // CHECKSTYLE:OFF
        System.out.println("Certificate:");
        System.out.println(ArmorUtils.toAsciiArmoredString(ourCert));

        System.out.println("Crypt-Only:");
        // CHECKSTYLE:ON
        ProducerOptions producerOptions = ProducerOptions
                .encrypt(new EncryptionOptions().addRecipient(ourCert).addRecipient(theirCert))
                .setFileName("msg.txt")
                .setModificationDate(new Date());

        generateMessage(producerOptions);

        // CHECKSTYLE:OFF
        System.out.println("Sign-Crypt:");
        // CHECKSTYLE:ON

        producerOptions = ProducerOptions
                .signAndEncrypt(new EncryptionOptions().addRecipient(ourCert).addRecipient(theirCert),
                        new SigningOptions().addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), ourKey, DocumentSignatureType.BINARY_DOCUMENT))
                .setFileName("msg.txt")
                .setModificationDate(new Date());

        generateMessage(producerOptions);
    }

    private void generateMessage(ProducerOptions producerOptions) throws PGPException, IOException {
        String data = "Hello World\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(producerOptions);

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), encryptionStream);
        encryptionStream.close();

        // CHECKSTYLE:OFF
        System.out.println(out);
        // CHECKSTYLE:ON
    }
}
