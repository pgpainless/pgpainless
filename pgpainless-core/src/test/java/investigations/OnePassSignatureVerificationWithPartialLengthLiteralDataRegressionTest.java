// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;

public class OnePassSignatureVerificationWithPartialLengthLiteralDataRegressionTest {

    /**
     * Signed and Encrypted Message created with PGPainless 0.2.9.
     * PGPainless versions 0.2.10 - 0.2.18 fail to decrypt this message, due to it failing to parse the signatures trailing
     * the literal data. The cause for this was not draining the literal data first before trying to parse the sigs.
     * This is likely caused by the literal data using a partial length encoding scheme, so the PGPObjectFactory did not yet
     * reach the signatures packets.
     *
     * As a fix, PGPainless now only tries to parse signatures from after the literal data packet, once the literal data
     * stream gets closed.
     */
    public static final String MSG = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "aEY0RHRHcWVYOENCUGRzU0FRZEFVTjJrSkZNb2lJUHhCUEFSWkZodnJxU2FGd090\n" +
            "c3llR2pkU1l4bS9UdFJRd01JK09PUGJYVjlnUEM3VEZFemlKWmRmL0ZxcUVaQTNV\n" +
            "ZkhIeEo3Y0hnWlhQWWw1Q29LMU5aSW9NRC9udk1iT1poRjREYmtNdFV2TkpWL3dT\n" +
            "QVFkQW00b01SQXVVbTdYL1BZUTc3T3Q2ZUxwTWs2VDk3TmhHMzB6RFFDSUMvV1l3\n" +
            "TTUvZkR4dW1uVW5ucXNwVFVJSmhRMmVYM0I2R2NtVE5ZdXVmSUNIbGZKMU9UQk05\n" +
            "MklNMkVGWHU1M2x3TVBLYTB1a0IzRWltbmJRNUpCNTBpT2NUeDZCcDJQREJZK0VN\n" +
            "K29IdDVlUzFzOWxlZjJUNHdCY0w1ejFLU3hQTkRpODh6Skp6dTZ1b3BxMXFwdWVI\n" +
            "UDFtemYzN0NTY3lJTHpJK0lwRXVUbWwvODdyK294TWVQR3NvR3NwblBuUWFXa0xY\n" +
            "dzdGVHpnWUJ5SGxyS3gzTGJIT040bDFVbC90dnhMbFBwNE5aRmJQcjQwWlYxb0o4\n" +
            "eE9JczRTaXpZSTNDUGRXQmlNVXJiaDJRMEFBTkg4aWNyMjhDeUZneDFSenpGdFRZ\n" +
            "MzVjeE5HSXRRZzRoR3BNUmVOWDdWNHpWOFRsUkFJSEVtaFRCTHpGZXR4eWJCbFJh\n" +
            "c3l0SUN0eWVydnZiNTQ3V2htK2tDWUxRQUcyOUlwZXUxOWo2MnV1dHJjWm10YWJn\n" +
            "LzEyTG5HSEczRkxoMGxHTmNOZnd3OXN6VC9zV0RXM2swQ3RCdVpsSmFUVXFLYlY2\n" +
            "QkRsTjZMWXFvYi9ad01wcDE4WGVuTk5tU2ZsL2JpcHZ0UE1hMk5NdGVuWXV2SGVO\n" +
            "R2hZK3Q0MFE3NE5OYmJRV1dsVXFqakFYZ3NOaUhsTjhDV2Z3UG82Ykx1OW9PaEFL\n" +
            "eTgvbFlNL1dlL2hlUFFpVGpqUUVaM3J2OHVDVGdCekFuc2tqazd0bUVOdTdnclJz\n" +
            "WjBSdzlYelRwTzJlTCtHRmV3VlhOMzNWUzFHVnR5QTMyVFRCd1ZDcStaNEtCMXRX\n" +
            "MVFIRUlDekc2UldsMkR5djBmZENpc2FoQU5SLzBmQXRrZm0wU3k1R1htWm5pWU9L\n" +
            "MkhiN2NZeHEzREs1MHowWTN4WkdiemE4L2VUMzlPTG1jMG5DdWQ5cktHaUkya0Er\n" +
            "a0NDQzF5UUlrek9zZDZlU1pFR1FncFV5UHlxdDRNQUhYeDcxUkFuR0NiWW9OVkRY\n" +
            "aUQwZ0d0M2lZRHFJV1N0TGErek1xbkJWN085Z3lSZFFVN2lXR25CeW9QNnlXc1Nk\n" +
            "aVBRSW5RR3RVSFZabU0wQnBwUk45ZUo0QlVJd2RvY0lIRldjZ0xNQjNiYlBDWHVF\n" +
            "bGl6N1ZPSHBFVWVYVmNWNWl6Z3NVUEJOSVVOZWxHcElrSk5Xa0lSSndMSFVnUlR0\n" +
            "SEh1ZFMyNnJZeURoU0tGcjdiM01HdWwyVU9GdTFlM0FzK24yVkJjcGN0ZHFtTGxG\n" +
            "THU3ZGxHMGJ0dHJQVWhaYyt4NjlFenUraTRtamRoZzZyVC9ydnYvRTJmRTRUVlpN\n" +
            "MGExbk5CUG40UT09\n" +
            "=mKyE\n" +
            "-----END PGP MESSAGE-----";

    public static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 23A2 3010 2038 66BC B390  8598 BB0C CFD4 57D4 DE77\n" +
            "Comment: xmpp:one@exampletwo.org\n" +
            "\n" +
            "lFgEYXQMCRYJKwYBBAHaRw8BAQdA1NhQdMUKkiwSI92ETqlY2lrAt4EbehgzpWMs\n" +
            "sm1Ke34AAP4sx3S3r0qoNpGyi3o7zfet60xIIkw9qKNdnYQyvouFhRFftBd4bXBw\n" +
            "Om9uZUBleGFtcGxldHdvLm9yZ4h4BBMWCgAgBQJhdAwJAhsBBRYCAwEABRUKCQgL\n" +
            "BAsJCAcCHgECGQEACgkQuwzP1FfU3ncAWQD/dUR7rbOpV8H4CTIpDJXiDuWi1vkC\n" +
            "Rmm5jFQsJlrIzZEA/0aZSEXH3Gj5OdQGy9qKrvqGkq7idjrTkh3gYiWRB+EOnF0E\n" +
            "YXQMCRIKKwYBBAGXVQEFAQEHQCobua4HJAsmfCB9TFjBSRfP1FEIEht4MMl4rHN4\n" +
            "eWc0AwEIBwAA/0Tmh56XX8bVDof1VVCdapcCC+LAA3wSH5SfP+EVaIJoD8WIdQQY\n" +
            "FgoAHQUCYXQMCQIbDAUWAgMBAAUVCgkICwQLCQgHAh4BAAoJELsMz9RX1N533dQB\n" +
            "ANRojORnaZw224DRVhONAuQazhKZz3e13MhyTFi91BhmAP9chFgUkvpiorQ6I65D\n" +
            "iCM315VHIvorrIElhKDtYu65CZxYBGF0DAkWCSsGAQQB2kcPAQEHQB3vy1KMKzDG\n" +
            "/yooOsvfNXtdFh8ROWWth2CZAh1rt3fdAAD+KVMkDED4xf7h1/aAunFAmdZ+xGTo\n" +
            "uPbTr8vWQMrVUFAUi4jVBBgWCgB9BQJhdAwJAhsCBRYCAwEABRUKCQgLBAsJCAcC\n" +
            "HgFfIAQZFgoABgUCYXQMCQAKCRDFaY6lJy4mR/FEAP9dHZi975eqlSdRa5pEn1xz\n" +
            "TLBfz2mAfWLQEr2kWLLVRAD+JBsyldKsUF8q1m/D/ty0lUUSGslgOhTcEoXxx3yC\n" +
            "1wwACgkQuwzP1FfU3neefwEA82brBIEKARYD/zHwNEPGLZweZHLPV5Iu9dmBw3l9\n" +
            "tmoA/RlQYaAKD86S1ZcfPIbjDIZkL9sjFh5tK0+mSl8rv4UH\n" +
            "=/1RX\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: FC0A 2CB3 F757 8B26 442C  7091 A7BA 7031 BD1E 0D5F\n" +
            "Comment: xmpp:one@exampleone.org\n" +
            "\n" +
            "mDMEYXQMCRYJKwYBBAHaRw8BAQdA01hwFPFYUpsGGUpf21BUlwoL9tVVAnR3sS+J\n" +
            "UZSUlka0F3htcHA6b25lQGV4YW1wbGVvbmUub3JniHgEExYKACAFAmF0DAkCGwEF\n" +
            "FgIDAQAFFQoJCAsECwkIBwIeAQIZAQAKCRCnunAxvR4NX+f7AQCjzT+r25dDlUpp\n" +
            "tocSQtgEmWZabwB41ykD/XfyBtM0RAD/ba4yYv+f/4mX7u3XpJxkrKFs/bHwyWsR\n" +
            "VapeUGxhKwa4OARhdAwJEgorBgEEAZdVAQUBAQdAlbrJ+h8CygRFZBsx+Rsm4Kp+\n" +
            "VCB7yUR2IxOrmiGqUlsDAQgHiHUEGBYKAB0FAmF0DAkCGwwFFgIDAQAFFQoJCAsE\n" +
            "CwkIBwIeAQAKCRCnunAxvR4NX3bmAP4mTtMWgKl7RkAB/pSLMJ4bbTMSMUJCH/jS\n" +
            "qz/PNtmVrgD+JLrWg2+hNPAA8zJx8LH73G4YzZMSQ0CBd9nmWRZr3w+4MwRhdAwJ\n" +
            "FgkrBgEEAdpHDwEBB0BrLuiD0Xb6/N66IehUl77qh/Q0vDa8ack6TcOIwxZsHIjV\n" +
            "BBgWCgB9BQJhdAwJAhsCBRYCAwEABRUKCQgLBAsJCAcCHgFfIAQZFgoABgUCYXQM\n" +
            "CQAKCRD97UDyQowaGe1MAPwJeSe2vkEcMIk711lBbAsambR7D72XVyc0F8maniUy\n" +
            "LwD8Dbgx8O0bCcd7fcXztfyZe8OtGKQk19fSLd+xp5VThwkACgkQp7pwMb0eDV8y\n" +
            "aQEA+g10lq+1gkaLBXZbc/mUJ4odIjYBk0JdGgU8oTAZd58A/2UT9C5G9ht/lMhK\n" +
            "hISFnP6CXwvy6L1XA9bjXQJ0unMF\n" +
            "=OyZq\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @Test
    public void testDecryptAndVerify_0_2_9_message() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(CERT);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ByteArrayOutputStream dearmored = new ByteArrayOutputStream();
        ArmoredInputStream armorIn = new ArmoredInputStream(new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8)));
        Streams.pipeAll(armorIn, dearmored);
        armorIn.close();

        ByteArrayInputStream in = new ByteArrayInputStream(dearmored.toByteArray());

        DecryptionStream decryptionStream = PGPainless.getInstance().processMessage()
                .onInputStream(in)
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(cert)
                        .addDecryptionKey(secretKeys));

        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
        decryptionStream.getMetadata();
    }
}
