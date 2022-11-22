// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;

/**
 * This class contains examples on how to decrypt encrypted, and verify signed messages.
 */
public class DecryptOrVerify {

    /**
     * The secret key.
     */
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: AA21 9149 3B35 E679 8876  DE43 B0D7 8185 F639 B6C9\n" +
            "Comment: Signora <signora@pgpainless.org>\n" +
            "\n" +
            "lFgEYVGUbRYJKwYBBAHaRw8BAQdAki59UUbUouvfd+4hoSAQ79He7cdmTyYTu3Su\n" +
            "9Ww0isQAAQCvyi79y6YNzxdQpN8HLPmBd+zq6o/RNK4cBeN+RJrxiBHbtCBTaWdu\n" +
            "b3JhIDxzaWdub3JhQHBncGFpbmxlc3Mub3JnPoh4BBMWCgAgBQJhUZRtAhsBBRYC\n" +
            "AwEABRUKCQgLBAsJCAcCHgECGQEACgkQsNeBhfY5tskOqgEA3fDHE1n081xiseTl\n" +
            "aXV1A/6aXvsnxVo+Lj35Mn7CarwBAO4PVjHvvUydTla3D5JHhZ0p4P5hSG7kPPrB\n" +
            "d3nmbH0InF0EYVGUbRIKKwYBBAGXVQEFAQEHQFzDN2Tuaxim9YFRRXeRZyDC42KF\n" +
            "9DSohUXEJ/TrM7MlAwEIBwAA/3h1IaQBIGlNZ6TSsuuryW8KtwdxI4Sd1JDzsVML\n" +
            "2SGQEFKIdQQYFgoAHQUCYVGUbQIbDAUWAgMBAAUVCgkICwQLCQgHAh4BAAoJELDX\n" +
            "gYX2ObbJBzwBAM4RYBuRsRTmEFTrc7FyAqqSrCVpyLkrnYqPTZriySX0AP9K+N1d\n" +
            "LIDRkHW7EbK2ITRu6nemFu00+H1bInTCUVxtAZxYBGFRlG0WCSsGAQQB2kcPAQEH\n" +
            "QOzydmmSnNw/NoWi0b0pODLNbT2VUFNFurxBoWj8T2oLAAD+Nbk5mZVQ91pDV6Bp\n" +
            "SAjCP9/e7odHtipsdlG9lszzC98RcIjVBBgWCgB9BQJhUZRtAhsCBRYCAwEABRUK\n" +
            "CQgLBAsJCAcCHgFfIAQZFgoABgUCYVGUbQAKCRBaxbg/GlrWhx43AP40HxpvHNL5\n" +
            "m953hWBxZvzIpt98E8+bfR4rCyHY6A5rzQEA8BUI6oqsEPKlGiETYntk7fFhOIyJ\n" +
            "bRH+a/LsdaxjpQwACgkQsNeBhfY5tskKHQEA+aanF6ZnSatjDdiKEehYmbqr4BTc\n" +
            "UDnu37YkbgLlqPIBAJrPT5XS9oVa5xMsK+c3shnmPVQuK9r/AGwlligJprYH\n" +
            "=JHMt\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    /**
     * Protector to unlock the secret key.
     * Since the key is not protected, it is enough to use an unprotectedKeys implementation.
     *
     * For more info on how to use the {@link SecretKeyRingProtector}, see {@link UnlockSecretKeys}.
     */
    private static final SecretKeyRingProtector keyProtector = SecretKeyRingProtector.unprotectedKeys();

    /**
     * The plaintext message.
     */
    private static final String PLAINTEXT = "Hello, World!\n";

    /**
     * The {@link #PLAINTEXT} message, but signed using inband signatures.
     */
    private static final String INBAND_SIGNED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "owGbwMvMyCUWdXSHvVTUtXbG0yJJDCDgkZqTk6+jEJ5flJOiyNVRysIoxsXAxsqU\n" +
            "GDiVjUGRUwCmQUyRRWnOn9Z/PIseF3Yz6cCEL05nZDj1OClo75WVTjNmJPemW6qV\n" +
            "6ki//1K1++2s0qTP+0N11O4z/BVLDDdxnmQryS+5VXjBX7/0Hxnm/eqeX6Zum35r\n" +
            "M8e7ufwA\n" +
            "=RDiy\n" +
            "-----END PGP MESSAGE-----";

    /**
     * The {@link #PLAINTEXT} message, but signed using the cleartext signature framework.
     */
    private static final String CLEARTEXT_SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "Hello, World!\n" +
            "\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iHUEARYKAAYFAmFR1WIAIQkQWsW4Pxpa1ocWIQQinPyF/gyi43GLAixaxbg/GlrW\n" +
            "h7qwAP9Vq0PfDdGpM+n4wfR162XBvvVU8KNl+vJI3u7Ghlj0zwEA1VMgwNnCRb9b\n" +
            "QUibivG5Slahz8l7PWnGkxbB2naQxgw=\n" +
            "=oNIK\n" +
            "-----END PGP SIGNATURE-----";

    /**
     * The {@link #PLAINTEXT} message, but encrypted for the {@link #certificate}.
     */
    private static final String ENCRYPTED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4DwqNy0B3ItTkSAQdArkuJHqPTVX+UaqQtHzppwOZDK0TfH1f/fAjrZaso/DUw\n" +
            "ne6Xc1HYG+gTBWEQUw09m5b/f0E7DSeIg/ai/HKnF8mBSIQhphPR4yVAWypOOUmh\n" +
            "0kABCiGjaJQyAzF/VtzC+ZVU67DfBl24CEPaRMumxieVUqo/VYWy3zyzE6H1zMqq\n" +
            "/lWeVnK7NwtfArlhpRcph0S8\n" +
            "=1cyl\n" +
            "-----END PGP MESSAGE-----\n";

    /**
     * The {@link #PLAINTEXT} message signed by the {@link #secretKey} and encrypted for the {@link #certificate}.
     */
    private static final String ENCRYPTED_AND_SIGNED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4DwqNy0B3ItTkSAQdAGqwFJ6SRW6It9w+RBudeGbdUj8OZqwApqyvwbKUzJiYw\n" +
            "WAcJOrGIbrK9bKzJdCLbVYkegILb6vqTuamU8iYDCccstV4Y2w0kT5ynHHPVFKfg\n" +
            "0r8BUe/Mi8zL0Af6K2r6A9gq/Q8vmscoOB5mI5Yxrk48+rPcp0rZbSu9rC9pHZfs\n" +
            "hhvxwGwG8EZm14pseHUZdoKldUD8tCbhkS7wDMOHzA1Fo1m1Yyjhe4kBaCrn9zhP\n" +
            "YSeOzHtMxk5JBcrZW+LMMuRGNBzxc0R1yirqk8yymF1qzTTuYqziO0QxbW1gU00F\n" +
            "ewdovd7Cx1Il8ONgRzGS3Wyb+iORNuhLpw+w2SV74Kg8XWLD7pDFgOuFZw39b+0X\n" +
            "Nw==\n" +
            "=9PiO\n" +
            "-----END PGP MESSAGE-----";

    private static PGPSecretKeyRing secretKey;
    private static PGPPublicKeyRing certificate;

    @BeforeAll
    public static void prepare() throws IOException {
        // read the secret key
        secretKey = PGPainless.readKeyRing().secretKeyRing(KEY);
        // certificate is the public part of the key
        certificate = PGPainless.extractCertificate(secretKey);
    }

    /**
     * This example demonstrates how to decrypt an encrypted message using a secret key.
     *
     * @throws PGPException
     * @throws IOException
     */
    @Test
    public void decryptMessage() throws PGPException, IOException {
        ConsumerOptions consumerOptions = new ConsumerOptions()
                .addDecryptionKey(secretKey, keyProtector); // add the decryption key ring

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();
        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ENCRYPTED.getBytes(StandardCharsets.UTF_8));

        // The decryption stream is an input stream from which we read the decrypted data
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(consumerOptions);

        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close(); // remember to close the stream!

        // The metadata object contains information about the message
        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncrypted()); // message was encrypted
        assertTrue(metadata.isEncryptedFor(secretKey));
        assertFalse(metadata.isVerifiedSigned()); // We did not do any signature verification

        // The output stream now contains the decrypted message
        assertEquals(PLAINTEXT, plaintextOut.toString());
    }

    /**
     * In this example, an encrypted and signed message is processed.
     * The message gets decrypted using the secret key and the signatures are verified using the certificate.
     *
     * @throws PGPException
     * @throws IOException
     */
    @Test
    public void decryptMessageAndVerifySignatures() throws PGPException, IOException {
        ConsumerOptions consumerOptions = new ConsumerOptions()
                .addDecryptionKey(secretKey, keyProtector) // provide the secret key of the recipient for decryption
                .addVerificationCert(certificate); // provide the signers public key for signature verification

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();
        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ENCRYPTED_AND_SIGNED.getBytes(StandardCharsets.UTF_8));

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(consumerOptions);

        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close(); // remember to close the stream to finish signature verification

        // metadata with information on the message, like signatures
        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncrypted()); // messages was in fact encrypted
        assertTrue(metadata.isEncryptedFor(certificate));
        assertTrue(metadata.isVerifiedSigned()); // the signatures were actually correct
        assertTrue(metadata.isVerifiedSignedBy(certificate)); // the signatures could be verified using the certificate

        assertEquals(PLAINTEXT, plaintextOut.toString());
    }

    /**
     * In this example, signed messages are verified.
     * The example shows that verification of inband signed, and cleartext signed messages works the same.
     * @throws PGPException
     * @throws IOException
     */
    @Test
    public void verifySignatures() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(certificate); // provide the signers certificate for verification of signatures

        for (String signed : new String[] {INBAND_SIGNED, CLEARTEXT_SIGNED}) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(signed.getBytes(StandardCharsets.UTF_8));

            DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(in)
                    .withOptions(options);

            Streams.pipeAll(verificationStream, out);
            verificationStream.close(); // remember to close the stream to finish sig verification

            // Get the metadata object for information about the message
            MessageMetadata metadata = verificationStream.getMetadata();
            assertTrue(metadata.isVerifiedSigned()); // signatures were verified successfully
            assertTrue(metadata.isVerifiedSignedBy(certificate));
            // The output stream we piped to now contains the message
            assertEquals(PLAINTEXT, out.toString());
        }
    }

    /**
     * This example shows how to create - and verify - cleartext signed messages.
     * @throws PGPException
     * @throws IOException
     */
    @Test
    public void createAndVerifyCleartextSignedMessage() throws PGPException, IOException {
        // In this example we sign and verify a number of different messages one after the other
        for (String msg : new String[] {"Hello World!", "- Hello - World -", "Hello, World!\n", "Hello\nWorld!"}) {
            // we need to read the plaintext message from somewhere
            ByteArrayInputStream in = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8));
            // and write the signed message to an output stream
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            SigningOptions signingOptions = SigningOptions.get();
            // for cleartext signed messages, we need to add a detached signature...
            signingOptions.addDetachedSignature(keyProtector, secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT);
            ProducerOptions producerOptions = ProducerOptions.sign(signingOptions)
                    .setCleartextSigned(); // and declare that the message will be cleartext signed

            // Create the signing stream
            EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(out) // on the output stream
                    .withOptions(producerOptions); // with the options

            Streams.pipeAll(in, signingStream); // pipe the plaintext message into the signing stream
            signingStream.close(); // remember to close the stream to finish the signatures

            // Now the output stream contains the signed message
            byte[] signedMessage = out.toByteArray();

            // Verification
            // we need to read the signed message
            ByteArrayInputStream signedIn = new ByteArrayInputStream(signedMessage);

            // and pass it to the decryption stream
            DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(signedIn)
                    .withOptions(new ConsumerOptions().addVerificationCert(certificate));

            // plain will receive the plaintext message
            ByteArrayOutputStream plain = new ByteArrayOutputStream();
            Streams.pipeAll(verificationStream, plain);

            verificationStream.close(); // as always, remember to close the stream

            // Metadata will confirm that the message was in fact signed
            MessageMetadata metadata = verificationStream.getMetadata();
            assertTrue(metadata.isVerifiedSigned());
            // compare the plaintext to what we originally signed
            assertArrayEquals(msg.getBytes(StandardCharsets.UTF_8), plain.toByteArray());
        }
    }
}
