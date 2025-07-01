// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

public class SignedMessageVerificationWithoutCertIsStillSignedTest {

    private static final String message = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "owGbwMvMwCGmFN+gfIiXM5zxtG4SQ2Iw74rgzPS81BSFktSKEoW0/CKFlNS0xNKc\n" +
            "Eoe0nPzy5KLKghK9ktTiEq6OXhYGMQ4GUzFFFtvXL7+VX9252+LpIheYcaxMQLMO\n" +
            "iMtg183AxSkAUynizshwbBMnx4e4tn6NgJYtG/od3HL1y26GvpgqUtr2o37HpC+v\n" +
            "GRmudmly/g+Osdt3t6Rb+8t8i8Y94ZJ3P/zNlk015FihXM0JAA==\n" +
            "=A8uF\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void verifyMissingVerificationCertOptionStillResultsInMessageIsSigned() throws IOException, PGPException {
        ConsumerOptions withoutVerificationCert = ConsumerOptions.get();
        DecryptionStream verificationStream = PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)))
                .withOptions(withoutVerificationCert);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(verificationStream, out);
        verificationStream.close();

        MessageMetadata metadata = verificationStream.getMetadata();

        assertFalse(metadata.isUsingCleartextSignatureFramework());
        assertTrue(metadata.hasRejectedSignatures(), "Message is signed, even though we miss the verification cert.");
        assertFalse(metadata.isVerifiedSigned(), "Message is not verified because we lack the verification cert.");
    }
}
