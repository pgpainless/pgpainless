// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;

public class Sign {

    private static PGPSecretKeyRing secretKey;
    private static SecretKeyRingProtector protector;

    @BeforeAll
    public static void prepare() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        secretKey = PGPainless.generateKeyRing().modernKeyRing("Emilia Example <emilia@example.org>", null);
        protector = SecretKeyRingProtector.unprotectedKeys(); // no password
    }

    /**
     * Demonstration of how to use the PGPainless API to sign some message using inband signatures.
     * The result is not human-readable, however the resulting text contains both the signed data and the signatures.
     */
    @Test
    public void inbandSignedMessage() throws PGPException, IOException {
        String message = "\"Derivative Works\" shall mean any work, whether in Source or Object form, that is based on (or derived from) the Work and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship. For the purposes of this License, Derivative Works shall not include works that remain separable from, or merely link (or bind by name) to the interfaces of, the Work and Derivative Works thereof.";
        InputStream messageIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(signedOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                                .addInlineSignature(protector, secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT))
                );

        Streams.pipeAll(messageIn, signingStream);
        signingStream.close();

        String signedMessage = signedOut.toString();
        assertTrue(signedMessage.startsWith("-----BEGIN PGP MESSAGE-----"));
        assertTrue(signedMessage.endsWith("-----END PGP MESSAGE-----\n"));
        assertFalse(signedMessage.contains("Derivative Works")); // hot human-readable
    }

    /**
     * Demonstration of how to create a detached signature for a message.
     * A detached signature can be distributed alongside the message/file itself.
     *
     * The message/file doesn't need to be altered for detached signature creation.
     */
    @Test
    public void detachedSignedMessage() throws PGPException, IOException {
        String message = "\"Contribution\" shall mean any work of authorship, including the original version of the Work and any modifications or additions to that Work or Derivative Works thereof, that is intentionally submitted to Licensor for inclusion in the Work by the copyright owner or by an individual or Legal Entity authorized to submit on behalf of the copyright owner. For the purposes of this definition, \"submitted\" means any form of electronic, verbal, or written communication sent to the Licensor or its representatives, including but not limited to communication on electronic mailing lists, source code control systems, and issue tracking systems that are managed by, or on behalf of, the Licensor for the purpose of discussing and improving the Work, but excluding communication that is conspicuously marked or otherwise designated in writing by the copyright owner as \"Not a Contribution.\"";

        InputStream messageIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        // The output stream below is named 'ignoreMe' because the output of the signing stream can be ignored.
        // After signing, you want to distribute the original value of 'message' along with the 'detachedSignature'
        // from below.
        ByteArrayOutputStream ignoreMe = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(ignoreMe)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                        .addDetachedSignature(protector, secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT))
                        .setAsciiArmor(false)
                );

        Streams.pipeAll(messageIn, signingStream);
        signingStream.close();

        EncryptionResult result = signingStream.getResult();

        PGPPublicKey signingKey = PGPainless.inspectKeyRing(secretKey).getSigningSubkeys().get(0);
        PGPSignature signature = result.getDetachedSignatures().get(new SubkeyIdentifier(secretKey, signingKey.getKeyID())).iterator().next();
        String detachedSignature = ArmorUtils.toAsciiArmoredString(signature.getEncoded());

        assertTrue(detachedSignature.startsWith("-----BEGIN PGP SIGNATURE-----"));

        // Now distribute 'message' and 'detachedSignature'.
    }

    /**
     * Demonstration of how to sign a text message in a way that keeps the message content
     * human-readable by utilizing the OpenPGP Cleartext Signature Framework.
     * The resulting message contains the original (dash-escaped) message and the signatures.
     */
    @Test
    public void cleartextSignedMessage() throws PGPException, IOException {
        String message = "" +
                "Copyright [yyyy] [name of copyright owner]\n" +
                "\n" +
                "Licensed under the Apache License, Version 2.0 (the \"License\");\n" +
                "you may not use this file except in compliance with the License.\n" +
                "You may obtain a copy of the License at\n" +
                "\n" +
                "    http://www.apache.org/licenses/LICENSE-2.0\n" +
                "\n" +
                "Unless required by applicable law or agreed to in writing, software\n" +
                "distributed under the License is distributed on an \"AS IS\" BASIS,\n" +
                "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n" +
                "See the License for the specific language governing permissions and\n" +
                "limitations under the License.";
        InputStream messageIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(signedOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                                .addDetachedSignature(protector, secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)) // Human-readable text document
                        .setCleartextSigned() // <- Explicitly use Cleartext Signature Framework!!!
                );

        Streams.pipeAll(messageIn, signingStream);
        signingStream.close();

        String signedMessage = signedOut.toString();

        assertTrue(signedMessage.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"));
        assertTrue(signedMessage.contains("WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND")); // msg is human readable
        assertTrue(signedMessage.endsWith("-----END PGP SIGNATURE-----\n"));
    }
}
