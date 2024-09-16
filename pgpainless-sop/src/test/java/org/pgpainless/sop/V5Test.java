// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.DecryptionResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class V5Test
{

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lGEFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd\n" +
            "fj75iux+my8QAAAAAAAiAQCHZ1SnSUmWqxEsoI6facIVZQu6mph3cBFzzTvcm5lA\n" +
            "Ng5ctBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0e8mHJGQC\n" +
            "X5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyICAQYVCgkI\n" +
            "CwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3wwJAXRJy9\n" +
            "M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2BZxmBVyR9OQSAAAA\n" +
            "MgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0YvYWWAoD\n" +
            "AQgHAAAAAAAiAP9OdAPppjU1WwpqjIItkxr+VPQRT8Zm/Riw7U3F6v3OiBFHiHoF\n" +
            "GBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACRWVabVAUCXJH05AIb\n" +
            "DAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijhob2U5AQC+RtOHCHx7\n" +
            "TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==\n" +
            "=IiS2\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String CERT = "\n" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mDcFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd\n" +
            "fj75iux+my8QtBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0\n" +
            "e8mHJGQCX5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyIC\n" +
            "AQYVCgkICwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3w\n" +
            "wJAXRJy9M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2Bbg8BVyR\n" +
            "9OQSAAAAMgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0\n" +
            "YvYWWAoDAQgHiHoFGBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACR\n" +
            "WVabVAUCXJH05AIbDAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijho\n" +
            "b2U5AQC+RtOHCHx7TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==\n" +
            "=WYfO\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";


    @Test
    public void encryptDecryptRoundtrip() throws IOException {
        SOPImpl sop = new SOPImpl();
        byte[] msg = "Hello!".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = sop.encrypt()
                .withCert(CERT.getBytes(StandardCharsets.UTF_8))
                .signWith(KEY.getBytes(StandardCharsets.UTF_8))
                .plaintext(msg)
                .toByteArrayAndResult()
                .getBytes();

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .verifyWithCert(CERT.getBytes(StandardCharsets.UTF_8))
                .withKey(KEY.getBytes(StandardCharsets.UTF_8))
                .ciphertext(ciphertext)
                .toByteArrayAndResult();
        byte[] plaintext = bytesAndResult.getBytes();
        DecryptionResult result = bytesAndResult.getResult();

        assertArrayEquals(msg, plaintext);
        assertFalse(result.getVerifications().isEmpty());
    }

    @Test
    public void decryptMessageFromGPG() throws IOException {
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "hF4D5FV8KwL/v0sSAQdAafQ8/zXGjQFVU0KAVrztae7K4Qt8OcwBplSV1SZgNn8w\n" +
                "h0kuBcw8OZTNvTT9xuMqObq0CNsWChOcDK9G/RzI6rn0loa9QYWyldNvL50bUqoe\n" +
                "1FMBCQIQZ79HHAZPmUiIXkhqVhKygmbm4DaXg+S6XZ1jPX6mzyeKlwDlNNrdFOll\n" +
                "QCbxAoki+JQdyZuDkrNXcabydZ9UBLUhBzAqCoCZyFIusc4utA==\n" +
                "=rwsk\n" +
                "-----END PGP MESSAGE-----\n";
        SOPImpl sop = new SOPImpl();
        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .withKey(KEY.getBytes(StandardCharsets.UTF_8))
                .ciphertext(msg.getBytes(StandardCharsets.UTF_8))
                .toByteArrayAndResult();
        DecryptionResult result = bytesAndResult.getResult();
        assertTrue(result.getVerifications().isEmpty()); // not signed

        byte[] plaintext = bytesAndResult.getBytes();
        assertArrayEquals("Hello World :)".getBytes(StandardCharsets.UTF_8), plaintext);
    }
}
