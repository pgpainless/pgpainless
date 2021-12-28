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
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.cleartext_signatures.InMemoryMultiPassStrategy;
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy;
import org.pgpainless.decryption_verification.cleartext_signatures.VerifyCleartextSignaturesImpl;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.consumer.CertificateValidator;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.SignatureVerifier;
import org.pgpainless.util.ArmorUtils;
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

    @Test
    public void cleartextSignVerification_InMemoryMultiPassStrategy()
            throws IOException, PGPException {
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();
        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(signingKeys);

        InMemoryMultiPassStrategy multiPassStrategy = MultiPassStrategy.keepMessageInMemory();
        options.setMultiPassStrategy(multiPassStrategy);
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(MESSAGE_SIGNED))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        OpenPgpMetadata result = decryptionStream.getResult();
        assertTrue(result.isVerified());

        PGPSignature signature = result.getVerifiedSignatures().values().iterator().next();

        assertEquals(signature.getKeyID(), signingKeys.getPublicKey().getKeyID());
        assertArrayEquals(MESSAGE_BODY, out.toByteArray());
    }

    @Test
    public void cleartextSignVerification_FileBasedMultiPassStrategy()
            throws IOException, PGPException {
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();
        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(signingKeys);

        File tempDir = TestUtils.createTempDirectory();
        File file = new File(tempDir, "file");
        MultiPassStrategy multiPassStrategy = MultiPassStrategy.writeMessageToFile(file);
        options.setMultiPassStrategy(multiPassStrategy);
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(MESSAGE_SIGNED))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        OpenPgpMetadata result = decryptionStream.getResult();
        assertTrue(result.isVerified());

        PGPSignature signature = result.getVerifiedSignatures().values().iterator().next();

        assertEquals(signature.getKeyID(), signingKeys.getPublicKey().getKeyID());
        FileInputStream fileIn = new FileInputStream(file);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        Streams.pipeAll(fileIn, bytes);
        fileIn.close();
        assertArrayEquals(MESSAGE_BODY, bytes.toByteArray());
    }

    @Test
    public void verifySignatureDetached()
            throws IOException, PGPException {
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();

        PGPSignature signature = SignatureUtils.readSignatures(SIGNATURE).get(0);
        PGPPublicKey signingKey = signingKeys.getPublicKey(signature.getKeyID());

        SignatureVerifier.initializeSignatureAndUpdateWithSignedData(signature, new ByteArrayInputStream(MESSAGE_BODY), signingKey);

        CertificateValidator.validateCertificateAndVerifyInitializedSignature(signature, signingKeys, PGPainless.getPolicy());
    }

    public static void main(String[] args) throws IOException {
        // CHECKSTYLE:OFF
        PGPPublicKeyRing keys = TestKeys.getEmilPublicKeyRing();
        System.out.println(ArmorUtils.toAsciiArmoredString(keys));
        System.out.println(new String(MESSAGE_SIGNED));
        System.out.println(new String(MESSAGE_BODY));
        System.out.println(new String(SIGNATURE));
        // CHECKSTYLE:ON
    }

    @Test
    public void testOutputOfSigVerification()
            throws IOException, PGPException {
        PGPSignature signature = SignatureUtils.readSignatures(SIGNATURE).get(0);

        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(TestKeys.getEmilPublicKeyRing())
                .addVerificationOfDetachedSignature(signature);

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(MESSAGE_BODY))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
        assertEquals(1, metadata.getVerifiedSignatures().size());
    }

    @Test
    public void consumingInlineSignedMessageWithCleartextSignedVerificationApiThrowsWrongConsumingMethodException()
            throws IOException {
        String inlineSignedMessage = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "kA0DAQoTVzbmkxrPNwwBy8BJYgAAAAAAQWgsIEp1bGlldCwgaWYgdGhlIG1lYXN1\n" +
                "cmUgb2YgdGh5IGpveQpCZSBoZWFwZWQgbGlrZSBtaW5lLCBhbmQgdGhhdCB0aHkg\n" +
                "c2tpbGwgYmUgbW9yZQpUbyBibGF6b24gaXQsIHRoZW4gc3dlZXRlbiB3aXRoIHRo\n" +
                "eSBicmVhdGgKVGhpcyBuZWlnaGJvciBhaXIsIGFuZCBsZXQgcmljaCBtdXNpY+KA\n" +
                "mXMgdG9uZ3VlClVuZm9sZCB0aGUgaW1hZ2luZWQgaGFwcGluZXNzIHRoYXQgYm90\n" +
                "aApSZWNlaXZlIGluIGVpdGhlciBieSB0aGlzIGRlYXIgZW5jb3VudGVyLoh1BAET\n" +
                "CgAGBQJhK2q9ACEJEFc25pMazzcMFiEET2ZcTcLEZgvGQl5BVzbmkxrPNwxr8gD+\n" +
                "MDfg+qccpsoJVgHIW8mRPBQowXDyw+oNHsf28ii+/pEBAO/RXhFkZBPzlfDJMJVT\n" +
                "UwJJeuna1R4yOoWjq0zqRvrg\n" +
                "=dBiV\n" +
                "-----END PGP MESSAGE-----\n";

        PGPPublicKeyRing certificate = TestKeys.getEmilPublicKeyRing();
        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(certificate);

        assertThrows(WrongConsumingMethodException.class, () ->
                new VerifyCleartextSignaturesImpl()
                        .onInputStream(new ByteArrayInputStream(inlineSignedMessage.getBytes(StandardCharsets.UTF_8)))
                        .withOptions(options)
                        .getVerificationStream());
    }

    @Test
    public void getDecoderStreamMistakensPlaintextForBase64RegressionTest()
            throws PGPException, IOException {
        String message = "Foo\nBar"; // PGPUtil.getDecoderStream() would mistaken this for base64 data
        ByteArrayInputStream msgIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));

        PGPSecretKeyRing secretKey = TestKeys.getEmilSecretKeyRing();
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign().onOutputStream(signedOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT))
                        .setCleartextSigned());

        Streams.pipeAll(msgIn, signingStream);
        signingStream.close();

        String signed = signedOut.toString();

        ByteArrayInputStream signedIn = new ByteArrayInputStream(signed.getBytes(StandardCharsets.UTF_8));
        DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
                .onInputStream(signedIn)
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(TestKeys.getEmilPublicKeyRing()));

        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();
        Streams.pipeAll(verificationStream, msgOut);
        verificationStream.close();

        OpenPgpMetadata metadata = verificationStream.getResult();
        assertTrue(metadata.isVerified());
    }

    @Test
    public void testDecryptionOfVeryLongClearsignedMessage()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        String message = randomString(28, 4000);

        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(
                        SigningOptions.get()
                                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(),
                                        secretKeys, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                ).setCleartextSigned());

        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptionStream);
        encryptionStream.close();

        String cleartextSigned = out.toString();

        ByteArrayInputStream in = new ByteArrayInputStream(cleartextSigned.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(PGPainless.extractCertificate(secretKeys)));

        out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
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
