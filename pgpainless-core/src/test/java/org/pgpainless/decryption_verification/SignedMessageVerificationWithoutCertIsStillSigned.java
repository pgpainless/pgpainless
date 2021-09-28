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
package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class SignedMessageVerificationWithoutCertIsStillSigned {

    private static final String message = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "owGbwMvMwCGmFN+gfIiXM5zxtG4SQ2Iw74rgzPS81BSFktSKEoW0/CKFlNS0xNKc\n" +
            "Eoe0nPzy5KLKghK9ktTiEq6OXhYGMQ4GUzFFFtvXL7+VX9252+LpIheYcaxMQLMO\n" +
            "iMtg183AxSkAUynizshwbBMnx4e4tn6NgJYtG/od3HL1y26GvpgqUtr2o37HpC+v\n" +
            "GRmudmly/g+Osdt3t6Rb+8t8i8Y94ZJ3P/zNlk015FihXM0JAA==\n" +
            "=A8uF\n" +
            "-----END PGP MESSAGE-----\n";
    private static final String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "lIYEYIq7phYJKwYBBAHaRw8BAQdAat45rrh+gvQwWwJw5eScq3Pdxt/8d+lWNVSm\n" +
            "kImXcRP+CQMCvWfx3mzDdd5g6c59LcPqADK0p70/7ZmTkp3ZC1YViTprg4tQt/PF\n" +
            "QJL+VPCG+BF9bWyFcfxKe+KAnXRTWml5O6xrv6ZkiNmAxoYyO1shzLQWZGVmYXVs\n" +
            "dEBmbG93Y3J5cHQudGVzdIh4BBMWCgAgBQJgirumAhsDBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCHgECGQEACgkQIl+AI8INCVcysgD/cu23M07rImuV5gIl98uOnSIR+QnHUD/M\n" +
            "I34b7iY/iTQBALMIsqO1PwYl2qKwmXb5lSoMj5SmnzRRE2RwAFW3AiMCnIsEYIq7\n" +
            "phIKKwYBBAGXVQEFAQEHQA8q7iPr+0OXqBGBSAL6WNDjzHuBsG7uiu5w8l/A6v8l\n" +
            "AwEIB/4JAwK9Z/HebMN13mCOF6Wy/9oZK4d0DW9cNLuQDeRVZejxT8oFMm7G8iGw\n" +
            "CGNjIWWcQSvctBZtHwgcMeplCW7tmzkD3Nq/ty50lCwQQd6gZSXMiHUEGBYKAB0F\n" +
            "AmCKu6YCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRAiX4Ajwg0JV+sbAQCv4LVM\n" +
            "0+AN54ivWa4vPRyYOfSQ1FqsipkYLJce+xwUeAD+LZpEVCypFtGWQVdeSJVxIHx3\n" +
            "k40IfHsK0fGgR+NrRAw=\n" +
            "=osuI\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String passphrase = "android";

    @Test
    public void verifyMissingVerificationCertOptionStillResultsInMessageIsSigned() throws IOException, PGPException {
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(key);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(
                Passphrase.fromPassword(passphrase), secretKey);
        PGPPublicKeyRing cert = PGPainless.extractCertificate(secretKey);

        ConsumerOptions withoutVerificationCert = new ConsumerOptions();
        DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)))
                .withOptions(withoutVerificationCert);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(verificationStream, out);
        verificationStream.close();

        OpenPgpMetadata metadata = verificationStream.getResult();

        assertTrue(metadata.isSigned(), "Message is signed, even though we miss the verification cert.");
        assertFalse(metadata.isVerified(), "Message is not verified because we lack the verification cert.");
    }
}
