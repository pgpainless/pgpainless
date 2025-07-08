// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;
import sop.Verification;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SignatureFuzzTest {

    private final SOP sop = new SOPImpl();
    private final byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    private final String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: D7BC FF6B B105 40D9 87F9  CB6E 542D C9F6 FCAE AD63\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEaGzu+BYJKwYBBAHaRw8BAQdAlqjB241N44drAJvxa3wx0uRb5bxuVNXrCwPZ\n" +
            "yf4Qg+MAAQCpACcGmoOPZISRbMjRzI/0Wf5iIZwp7r9huzLe6NToBRFxtBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+wpUEExYKAEcFgmhs7vgJEFQtyfb8rq1j\n" +
            "FiEE17z/a7EFQNmH+ctuVC3J9vyurWMCngECmwEFFgIDAQAECwkIBwUVCgkICwWJ\n" +
            "CWYBfwKZAQAA1SMBAIuffSIKKkG73rWInDrfV6G0kCh/uP7Qf3Jh4A+x5BrvAP42\n" +
            "KANAmmLmDVsPGWEPEAlCAJFwKZvHzvYsk8dEFNZEDJxYBGhs7vgWCSsGAQQB2kcP\n" +
            "AQEHQOPChGD0z51fOsnFswJPNmhzxdhZHuXCxbEJ+/5WhU9QAAEA3i0J/Vbyhj92\n" +
            "kd8gsjLUIkbDHGGDb/vfRCgmRAySF1MOL8LAFQQYFgoAfQWCaGzu+AKeAQKbAgUW\n" +
            "AgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFgmhs7vgACgkQIvV9b29BRNSV1AEAtywX\n" +
            "h7bdVq0597D0JfASIvo/ksyHsTyf/JRVH6M0Gv0A/RvFJnVRt1EitamD8i2mX2H3\n" +
            "yC2lP2t1WzTafT7GzkYMAAoJEFQtyfb8rq1jhRABAIb/GkyCOlU02zfDMd5UHQ4J\n" +
            "EpexaSodCvrGcQMA5t2nAPsEPXQOl1AOdJoc/sICsVAi4DvxohelpWJ19ZUy7WYQ\n" +
            "CZxdBGhs7vgSCisGAQQBl1UBBQEBB0BeCegzdBr3B6+q3IBjkzNXPfLopNi2d+sL\n" +
            "9hcbV9ztDgMBCAcAAP9hFCttDV8qWyven96rQ0WKGfVo1bKp2EZHGUR7tIScWA9P\n" +
            "wnUEGBYKAB0Fgmhs7vgCngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRBULcn2/K6t\n" +
            "Y7GuAP9Kf1Ec1GJmZ99UHsgiN60os+6adMLj4G2ASiIbNSDvKgD9F/VLFIb/eN7k\n" +
            "JQp3E5C15x5pMMKEI/rjwdrKmYH3aAw=\n" +
            "=hnEg\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private final String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: D7BC FF6B B105 40D9 87F9  CB6E 542D C9F6 FCAE AD63\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "mDMEaGzu+BYJKwYBBAHaRw8BAQdAlqjB241N44drAJvxa3wx0uRb5bxuVNXrCwPZ\n" +
            "yf4Qg+O0HEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz7ClQQTFgoARwWCaGzu\n" +
            "+AkQVC3J9vyurWMWIQTXvP9rsQVA2Yf5y25ULcn2/K6tYwKeAQKbAQUWAgMBAAQL\n" +
            "CQgHBRUKCQgLBYkJZgF/ApkBAADVIwEAi599IgoqQbvetYicOt9XobSQKH+4/tB/\n" +
            "cmHgD7HkGu8A/jYoA0CaYuYNWw8ZYQ8QCUIAkXApm8fO9iyTx0QU1kQMuDMEaGzu\n" +
            "+BYJKwYBBAHaRw8BAQdA48KEYPTPnV86ycWzAk82aHPF2Fke5cLFsQn7/laFT1DC\n" +
            "wBUEGBYKAH0Fgmhs7vgCngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBYJo\n" +
            "bO74AAoJECL1fW9vQUTUldQBALcsF4e23VatOfew9CXwEiL6P5LMh7E8n/yUVR+j\n" +
            "NBr9AP0bxSZ1UbdRIrWpg/Itpl9h98gtpT9rdVs02n0+xs5GDAAKCRBULcn2/K6t\n" +
            "Y4UQAQCG/xpMgjpVNNs3wzHeVB0OCRKXsWkqHQr6xnEDAObdpwD7BD10DpdQDnSa\n" +
            "HP7CArFQIuA78aIXpaVidfWVMu1mEAm4OARobO74EgorBgEEAZdVAQUBAQdAXgno\n" +
            "M3Qa9wevqtyAY5MzVz3y6KTYtnfrC/YXG1fc7Q4DAQgHwnUEGBYKAB0Fgmhs7vgC\n" +
            "ngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRBULcn2/K6tY7GuAP9Kf1Ec1GJmZ99U\n" +
            "HsgiN60os+6adMLj4G2ASiIbNSDvKgD9F/VLFIb/eN7kJQp3E5C15x5pMMKEI/rj\n" +
            "wdrKmYH3aAw=\n" +
            "=4uX6\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @FuzzTest(
            maxDuration = "60s"
    )
    public void verifyFuzzedSig(FuzzedDataProvider provider) throws IOException {
        byte[] sig = provider.consumeBytes(1024);
        if (sig.length == 0) {
            return;
        }

        try {
            List<Verification> verifs = sop.verify()
                    .cert(cert.getBytes(StandardCharsets.UTF_8))
                    .signatures(sig)
                    .data(data);

            if (verifs.isEmpty()) {
                return;
            }

            for (Verification v : verifs) {
                System.out.println(v.toString());
            }
        } catch (SOPGPException.NoSignature e) {
            // ignore
        } catch (SOPGPException.BadData e) {
            // expected
        }
    }
}
