// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TestIgnoreAsciiArmorCRCOnProcessing {

    @Test
    public void processMessageWithBrokenCRCAndIgnoreFlag() throws PGPException, IOException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 0139 6ACD 90AD 296F 36ED  EDA8 A68E 449A 737B 7445\n" +
                "Comment: Alice\n" +
                "\n" +
                "lFgEajPghxYJKwYBBAHaRw8BAQdA2M4XmBjE98mnBAw4WoDdV39HpTh/IOFFJU+q\n" +
                "rszE0BQAAQCVLCaq81BuZLmw3Z9CDFSM09Yjep/F21RlPjxTwHdbXQ+0tAVBbGlj\n" +
                "ZcKfBBMWCgBRCRCmjkSac3t0RRahBAE5as2QrSlvNu3tqKaORJpze3RFBYJqM+CH\n" +
                "ApsBBRUKCQgLBRYCAwEABAsJCAcJJwkBCQIJAwgBAp4JBYkJZgGAApkBAADJ5wD9\n" +
                "GMogF3tONEjj9aSqWGd8vb8S9TC1okVowaWMvvBhEKcBAIqqQBLL7IPOTke+Wiig\n" +
                "GaPWbkHdxXB5zyhe8sXN/D4OnF0EajPghxIKKwYBBAGXVQEFAQEHQBD5PuEFi7E/\n" +
                "qcGNI819y8pgPZgvaqh0eMKpQ6gu8OgaAwEIBwAA/0mKuZwgw/SQWwPZkyYMRHqp\n" +
                "B+cVXpC4RfTsGYqTFjqYD93CeAQYFgoAKgkQpo5EmnN7dEUWoQQBOWrNkK0pbzbt\n" +
                "7aimjkSac3t0RQWCajPghwKbDAAAfFYA/22ww9bmCgPCDrHVC21n45tnZzU4lJYX\n" +
                "SbOhbGs+97KUAPwKndlwLDluGBA52TRwb2BZhIBNYrhRecqugBhybsteApxYBGoz\n" +
                "4IcWCSsGAQQB2kcPAQEHQD18GvjePIhZX1P2U08ZE7V672T26CGH2JDEepon6shO\n" +
                "AAD+L+T4o48mvgLVK2maooN+ND2gA9g6ZVKsJBnTLueNb+MQVMLALwQYFgoAoQkQ\n" +
                "po5EmnN7dEUWoQQBOWrNkK0pbzbt7aimjkSac3t0RQWCajPghwKbAnYgBBkWCgAd\n" +
                "BYJqM+CHFiEEP0w9v3bjlBlBqDq0C5gXfy8fPfsACgkQC5gXfy8fPfvQfAEA9Qsn\n" +
                "aqVNdpufxjyVVg5639y7SPEgVAIFAPUwiMLM4s0BAL2lrHmWUiW01mg9jGtMTB43\n" +
                "Sk74uDhz2lmFVQI9xjsNAABC+gEA/jWN+tYlXSD1LKjbarAMM6goVKZdLZQVvdeM\n" +
                "0o7jVHEA/2l0g+xY2wMbPiMMqRvsZU/eAGfKrVG1jBCN8NPV9JYC\n" +
                "=yN9G\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "kA0DAAoWC5gXfy8fPfsByxFiAAAAAABIZWxsbyBXb3JsZMJ1BAAWCgAnBYJqM+CI\n" +
                "CRALmBd/Lx89+xahBD9MPb9245QZQag6tAuYF38vHz37AACKlAD9H+MVCZ8Om7dF\n" +
                "HROYWSMxlNEwlkclaO9qeK/Nb+gj+OkBAPpBd4RcsX0kBmDyU5ljaIf0YVKF2Wgx\n" +
                "MaKwz0zpvHQA\n" +
                "=VD49\n" + // "=VD43\n"
                "-----END PGP MESSAGE-----";

        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.readKey().parseKey(KEY);
        ByteArrayInputStream bIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .setDisableAsciiArmorCRC(true) // ignore crc failures
                        .addVerificationCert(key.toCertificate()));

        Streams.drain(decIn);
        decIn.close();
    }
}
