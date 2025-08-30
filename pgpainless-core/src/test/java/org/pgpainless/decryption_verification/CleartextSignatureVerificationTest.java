// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.decryption_verification.cleartext_signatures.InMemoryMultiPassStrategy;
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.TestUtils;

public class CleartextSignatureVerificationTest {

    public static final byte[] MESSAGE_BODY = ("Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.").getBytes(StandardCharsets.UTF_8);
    public static final byte[] MESSAGE_SIGNED = ("-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iHUEARMKAB0WIQRPZlxNwsRmC8ZCXkFXNuaTGs83DAUCYJ/x5gAKCRBXNuaTGs83\n" +
            "DFRwAP9/4wMvV3WcX59Clo7mkRce6iwW3VBdiN+yMu3tjmHB2wD/RfE28Q1v4+eo\n" +
            "ySNgbyvqYYsNr0fnBwaG3aaj+u5ExiE=\n" +
            "=Z2SO\n" +
            "-----END PGP SIGNATURE-----").getBytes(StandardCharsets.UTF_8);
    public static final byte[] SIGNATURE = ("-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iHUEARMKAB0WIQRPZlxNwsRmC8ZCXkFXNuaTGs83DAUCYJ/x5gAKCRBXNuaTGs83\n" +
            "DFRwAP9/4wMvV3WcX59Clo7mkRce6iwW3VBdiN+yMu3tjmHB2wD/RfE28Q1v4+eo\n" +
            "ySNgbyvqYYsNr0fnBwaG3aaj+u5ExiE=\n" +
            "=Z2SO\n" +
            "-----END PGP SIGNATURE-----").getBytes(StandardCharsets.UTF_8);

    public static final String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    public static final Random random = new Random();
    private static final PGPainless api = PGPainless.getInstance();

    @Test
    public void cleartextSignVerification_InMemoryMultiPassStrategy()
            throws IOException, PGPException {
        OpenPGPCertificate signingCert = TestKeys.getEmilCertificate();
        ConsumerOptions options = ConsumerOptions.get(api)
                .addVerificationCert(signingCert);

        InMemoryMultiPassStrategy multiPassStrategy = MultiPassStrategy.keepMessageInMemory();
        options.setMultiPassStrategy(multiPassStrategy);
        DecryptionStream decryptionStream = api.processMessage()
                .onInputStream(new ByteArrayInputStream(MESSAGE_SIGNED))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        MessageMetadata result = decryptionStream.getMetadata();
        assertTrue(result.isVerifiedSigned());
        assertTrue(result.isUsingCleartextSignatureFramework());

        PGPSignature signature = result.getVerifiedSignatures().iterator().next().getSignature();

        assertTrue(signature.hasKeyIdentifier(signingCert.getKeyIdentifier()));
        assertArrayEquals(MESSAGE_BODY, out.toByteArray());
    }

    @Test
    public void cleartextSignVerification_FileBasedMultiPassStrategy()
            throws IOException, PGPException {
        OpenPGPCertificate signingCert = TestKeys.getEmilCertificate();
        ConsumerOptions options = ConsumerOptions.get(api)
                .addVerificationCert(signingCert);

        File tempDir = TestUtils.createTempDirectory();
        File file = new File(tempDir, "file");
        MultiPassStrategy multiPassStrategy = MultiPassStrategy.writeMessageToFile(file);
        options.setMultiPassStrategy(multiPassStrategy);
        DecryptionStream decryptionStream = api.processMessage()
                .onInputStream(new ByteArrayInputStream(MESSAGE_SIGNED))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        MessageMetadata result = decryptionStream.getMetadata();
        assertTrue(result.isVerifiedSigned());

        PGPSignature signature = result.getVerifiedSignatures().iterator().next().getSignature();

        assertTrue(signature.hasKeyIdentifier(signingCert.getKeyIdentifier()));
        FileInputStream fileIn = new FileInputStream(file);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        Streams.pipeAll(fileIn, bytes);
        fileIn.close();
        assertArrayEquals(MESSAGE_BODY, bytes.toByteArray());
    }

    public static void main(String[] args) throws IOException {
        // CHECKSTYLE:OFF
        OpenPGPCertificate cert = TestKeys.getEmilCertificate();
        System.out.println(cert.toAsciiArmoredString());
        System.out.println(new String(MESSAGE_SIGNED));
        System.out.println(new String(MESSAGE_BODY));
        System.out.println(new String(SIGNATURE));
        // CHECKSTYLE:ON
    }

    @Test
    public void testOutputOfSigVerification()
            throws IOException, PGPException {
        PGPSignature signature = SignatureUtils.readSignatures(SIGNATURE).get(0);

        ConsumerOptions options = ConsumerOptions.get(api)
                .addVerificationCert(TestKeys.getEmilCertificate())
                .addVerificationOfDetachedSignature(signature);

        DecryptionStream decryptionStream = api.processMessage()
                .onInputStream(new ByteArrayInputStream(MESSAGE_BODY))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        MessageMetadata metadata = decryptionStream.getMetadata();
        assertEquals(1, metadata.getVerifiedSignatures().size());
    }

    @Test
    public void getDecoderStreamMistakensPlaintextForBase64RegressionTest()
            throws PGPException, IOException {
        String message = "Foo\nBar"; // PGPUtil.getDecoderStream() would have mistaken this for base64 data
        ByteArrayInputStream msgIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));

        OpenPGPKey secretKey = TestKeys.getEmilKey();
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        EncryptionStream signingStream = api.generateMessage().onOutputStream(signedOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT))
                        .setCleartextSigned());

        Streams.pipeAll(msgIn, signingStream);
        signingStream.close();

        String signed = signedOut.toString();

        ByteArrayInputStream signedIn = new ByteArrayInputStream(signed.getBytes(StandardCharsets.UTF_8));
        DecryptionStream verificationStream = api.processMessage()
                .onInputStream(signedIn)
                .withOptions(ConsumerOptions.get(api)
                        .addVerificationCert(TestKeys.getEmilCertificate()));

        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();
        Streams.pipeAll(verificationStream, msgOut);
        verificationStream.close();

        MessageMetadata metadata = verificationStream.getMetadata();
        assertTrue(metadata.isVerifiedSigned());
    }

    @Test
    public void testDecryptionOfVeryLongClearsignedMessage()
            throws PGPException, IOException {
        String message = randomString(28, 4000);

        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(
                        SigningOptions.get(api)
                                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(),
                                        secretKeys, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                ).setCleartextSigned());

        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptionStream);
        encryptionStream.close();

        String cleartextSigned = out.toString();

        ByteArrayInputStream in = new ByteArrayInputStream(cleartextSigned.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = api.processMessage()
                .onInputStream(in)
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(secretKeys.toCertificate()));

        out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
    }

    @Test
    public void clearsignedMessageUtil_detachSignaturesFromInbandNonClearsignedMessageThrows() {
        // Message is inband signed, but does not use cleartext signature framework
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "owGbwMvMyCX29UzQdZ1/lUqMpw8YJDGAgJGjd3JgcqJTVUpylpOCmUK+l39asYGl\n" +
                "k1NkcYSxgkuaR26EQplppGVuREGqn3NBRJRXoVm4T1BuhoJjcllOYV5xhmVKloVz\n" +
                "UJaZQmhBSbqCr6uhQlVIkL9rqUJgaaWjpalCuVdiXkVhiFNuQHpmeLpChGNqVkG5\n" +
                "U1iBgqmvo79LXlFVWK5rpEGkh0dBfrB/ngKXj5FhVlZuUpllTk6xb3m5QlWUT3Gh\n" +
                "o7dCQXGIgnlwZkBYlI9FhEFAprdnkLGFe6KjZ2meQblCXkiWaWhUknl5YmmYb7JC\n" +
                "noJJeWZYXmJarpFvXkpKpbGXQkcpC6MYF4M6K1PShlmCnAKwsBBTZJktcnnrHYXL\n" +
                "h1oWr+qECTMw+O9i+KfUs3LXgzOuS102VbY+fLCqwFynLmyqVDE3b4Yu/5x68UCG\n" +
                "/35qnVwnbYX8YrK6j+UdabAo/HnvZL7jk7pjRg1n3TIy+QE=\n" +
                "=yFcL\n" +
                "-----END PGP MESSAGE-----";

        InputStream inputStream = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        assertThrows(WrongConsumingMethodException.class,
                () -> ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(inputStream, outputStream));
    }

    private String randomString(int maxWordLen, int wordCount) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < wordCount; i++) {
            sb.append(randomWord(maxWordLen)).append(' ');
            int n = random.nextInt(12);
            if (n == 11) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    private String randomWord(int maxWordLen) {
        int len = random.nextInt(maxWordLen);
        char[] word = new char[len];
        for (int i = 0; i < word.length; i++) {
            word[i] = alphabet.charAt(random.nextInt(alphabet.length()));
        }
        return new String(word);
    }
}
