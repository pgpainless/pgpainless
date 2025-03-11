// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.encryption_signing.CRLFGeneratorStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

public class CanonicalizedDataEncryptionTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9AF4 29C4 C389 CC11 1739  98E9 9F8E E9C5 3AE5 C1A4\n" +
            "Comment: Test <test@vanitasvi.tae>\n" +
            "\n" +
            "lQcYBGI8Y/cBEACHIx1hfYeTHZ39UGM5kuJBuvJOZXR60DppIkgjPWyc+p2mxXY5\n" +
            "tOl+xVSzWHudogtxM1kbpYghPXWOj7ssh7V+4OI1JIi3ODEuWozRN1HjqyY11ORg\n" +
            "ky6lmbZ0/YupTFbZ6H4yMoHbLPugN2fAdZLcpeVL0taQ04ImaNQnnGIiaCd9TxWN\n" +
            "UiQRouFFI2YSrE97x8+32VycxtCX11/DN7xU6v4SISL4NoIlhsBT+WhFCl/6ntwB\n" +
            "JXStwjN4Mp/gmmtu5EBDh+OYLq09z2jOzBTofhSRYz5wH0oNh1gj4CwwrkThvBMH\n" +
            "fl9pTKhwp3vL/76UkWJHu9OjCP6T2sPFeCuRPCBI9gDTpK1vkfQa0pj7X9hF+8we\n" +
            "TY6E1prcYbx/1sxO5EEVYDCqtmd5VDQd69uaC8/NWH0769bxbNZUc5EJ/PkFZXKJ\n" +
            "nCsjr8i29j6r7NbK6YlFxNj/CkbYfufzQ7moo9miGh1u3Pe0kbZpdYuPUnh3oVi3\n" +
            "px6L/IJxIR+owJLs9X+W/3bvP7OmYwHT3czwQ8/PrI+CuybFv+BDOKX1142zh1Qj\n" +
            "IEsc6Zx7wUMRH2qImRP7amuxP7npMaANp0GWNNWTgKHV+iLxbYDHnIX2qcPpWn4W\n" +
            "CRWshgulAzt9IP0AGErHw4FDXSzk4s9btRDL6MFYP/2+gG+L4cLlxEOarwARAQAB\n" +
            "AA/9HMu5vgVut0WPXeQcUK9g8Rqx+UybJnRqje6VKpUzKLwqjdfz2lYXj0DjTJgl\n" +
            "NzDJeWS0rzR1roeXHjq4asO8Q/4Nlb9kNo6NxE/dQ9Oi6n2U1dG4nG+gd/8qJwHE\n" +
            "Gd4/f42QHogurZKHR9umixdCpSvgkWiq+g9n42FhG9OyAZzqFUSd1hBTyUJI+F+T\n" +
            "p5T6Fuk79PQnTOz8k+575HBi/EFaxGg1OGj9EJwHLZ2uv093pkLlpITjuQbxysIW\n" +
            "2VhuXiHbI8i4EbyYg9xHfBF2vxfmsBhSvLeeIwXdHT/uiq0H1oYqE+W01Q5VsjOu\n" +
            "KIklhij4pUp7zXjkLoNmRhTWS3wXCLS/cwIpf37aZh5HJaP2BMorDoeJFlEVgBVT\n" +
            "VpiljD1IIQ3FvvZEK6p9GPMIzrW2EWa25Koi+ouFNoSxycAuuA1JdvsBZFTWaNG5\n" +
            "CyNvNp7ZhFTdL6rFmLo94M/326cF3DW5pW8BxQOj1VnE9jRWs6pqypEZ8k+L3eVi\n" +
            "WFS6ZECWy5nkew8QYtuuHb01XiJdKljO0Rrhni7cEbtGtgPwkfoELoo+yNC+AVuf\n" +
            "uqYDtY1PTcx9ndlV5gLabZpO7gCH8qvDrgDEHGwJogxNeHnXLI8Zz+ClWhS99C8Z\n" +
            "6gV5KZstg87ZK331LumY3TMt/FVROOzLtPrg3IubWfNGbfEIALWcuDBjYBs8XNqV\n" +
            "WizXB99ssslKwm79pggca5pM5wEryAwRN2Lsqcncd/sN3g0GhyqxKBnKkBvoayRP\n" +
            "zdQE5F0+ylL5FEDSaAyroDPUww0E7QYh7zm1WVDPZZLknn0r6Yq6yn0E+7R/fHe7\n" +
            "8NJu6C2veH+wYgh6cqVKXCAQccBj+K2r7dUExuldxGyuB5lbVcKTf8dgXqxGh3uw\n" +
            "CNA6tSL1OqqYxn2MME3xrFoBBxjttX2XQuQKdHD2CL9wySRkvFwgJb3KDZjh7K1B\n" +
            "yEbLLkMWUA2H6QF7Lnqq65rcjgfLvq64MSTfNiW0EL4hIBvAPpnK7LHCHkt6i3jC\n" +
            "3beoHfcIAL59K+pwtV9hPa3SQpZfYkumYxw3ixSh9UJ2bTUkecypCN+MrHDi6ALe\n" +
            "Thcfn6/fEbJXeKFC4OGqNW6aw2ArcJ5q1SFeV1bnTz0REdgaOZj/o71O5hdBjgEV\n" +
            "RjuK36PNmimJQKk3HZfBtb0FnfL6Cx5Q2gIG+wJDd0MyoSTpWNuUlav9TnxCEyeC\n" +
            "MQGxgEb0BrPX7xGLIVBcfkV3i5w77wbIk1vgZlNFyc4ecZbdBwFd1X140G7aVFik\n" +
            "LNaPY87WUbnzBN+P31KkQxgEOZNLt091XmDFbsbMGj7s7N0DPMMV9Vk8qy5VmlSg\n" +
            "Bh59FvQNaZfR/a0OE3cCLJlS7076mwkH/0Bc6Y7GKsYVdqhCLtw/IlNBAlGGUCM0\n" +
            "7h7glI40ET1X5ar1ABBC6FGwZO/QV0ynaVQuO0oCbn5uIZXIRdZ8AiBwf4E3LeaI\n" +
            "kSCOu81c/HXmNw78cx13uCkW18ReS+12ScXflSzvTGTsmdP8wuORBWxSHgJYv5qC\n" +
            "RXt3/hWb5dOm7nbhydqNdHvLSQ1d6Uky2OWVMQJuLlj1ZQ7wYShEOGRi3oJxUVT5\n" +
            "tO08dshzBaPdPKsz02ZDSKOnC1JR63jfONydwW3VoRFgtjV6kJ40XRJvP0uVbyye\n" +
            "E0RUBNao18tA2vT1iXkEiSHcU1ImewuXiOzcVeWIRU/b6j4Z+Of1iN52UbQZVGVz\n" +
            "dCA8dGVzdEB2YW5pdGFzdmkudGFlPokCTQQTAQoAQQUCYjxj9wkQn47pxTrlwaQW\n" +
            "IQSa9CnEw4nMERc5mOmfjunFOuXBpAKeAQKbBwUWAgMBAAQLCQgHBRUKCQgLApkB\n" +
            "AABFhA/+IULfY31WpA3y0EgpYQTDpg3jSKPGPRaDYlMAAkIlCjoAA0N3gTKtktmG\n" +
            "3tEQfwI0zYzVP+8FHlJ/5ovu6+qSIdAVA7YUewNLG2p6DlMW8Eysa/ARmbIrlN+R\n" +
            "bH+KgFNz3dS9zS6mvRu2m6a8qRFpW4iHAJctaV29Ff5sKppLjetdOH8wL/b7fE+O\n" +
            "mg/mrBRVVhqwSvAULoHAIix8vpdAr2iiHhGzvwDpqVirca15XoCaKKNlJfTaRH+J\n" +
            "5nqsABTKTrsOZyLW8OuQ8VaWGi4XZB2ansTMnH4m7RzWwXM+P2BjB9KEtClVgGxw\n" +
            "jHlEqbqtquaJW5hh7xjXRNZ45joTxQkepLZ8TM3hB6Ben4st893kffwur39mRWFe\n" +
            "u/KvvFdkQZuvWj+8Ng4uvWap+9KbGpam8ohZLY4OoR2d7/9ueikGmLyJFKjLDVWQ\n" +
            "Ya+inSUIDdyYvq7flHo0dXB7yftpvpOCQ9E/p2FmVDvvKsaRvAItQV8cX1RpYtGG\n" +
            "wdLQnmsIuRhV5j7OXv5zyQJvbvLgisl11VFWR7RNhJ9xNPbUTknCw1Ftp0nSXEnS\n" +
            "gl/0Z7KWoiY8sAn3o45KZRnq8uiF19kYXdrRWIFo1LtG68hjOYYRG5ejmCt6zx53\n" +
            "Zd+AyZA+lkh8uI921Nnio2g70zVVSKEVaJcWTlkVyKge2iV/YkQ=\n" +
            "=EyDf\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    String message = "Hello, World!\n";

    private static PGPSecretKeyRing secretKeys;
    private static PGPPublicKeyRing publicKeys;

    @BeforeAll
    public static void readKeys() throws IOException {
        secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        publicKeys = PGPainless.extractCertificate(secretKeys);
        // CHECKSTYLE:OFF
        System.out.println(PGPainless.asciiArmor(secretKeys));
        // CHECKSTYLE:ON
    }

    // NO CR/LF ENCODING PRIOR TO PROCESSING

    @Test
    public void noInputEncodingBinaryDataBinarySig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.BINARY, false);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void noInputEncodingBinaryDataTextSig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT, StreamEncoding.BINARY, false);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void noInputEncodingTextDataBinarySig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.TEXT, false);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void noInputEncodingTextDataTextSig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT, StreamEncoding.TEXT, false);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void noInputEncodingUtf8DataBinarySig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.UTF8, false);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void noInputEncodingUtf8DataTextSig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT, StreamEncoding.UTF8, false);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }
    // APPLY CR/LF ENCODING PRIOR TO PROCESSING

    @Test
    public void inputEncodingBinaryDataBinarySig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.BINARY, true);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void inputEncodingBinaryDataTextSig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT, StreamEncoding.BINARY, true);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void inputEncodingTextDataBinarySig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.TEXT, true);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void inputEncodingTextDataTextSig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT, StreamEncoding.TEXT, true);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void inputEncodingUtf8DataBinarySig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.UTF8, true);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @Test
    public void inputEncodingUtf8DataTextSig() throws PGPException, IOException {
        String msg = encryptAndSign(message, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT, StreamEncoding.UTF8, true);
        MessageMetadata metadata = decryptAndVerify(msg);

        if (!metadata.isVerifiedSigned()) {
            // CHECKSTYLE:OFF
            System.out.println("Not verified. Session-Key: " + metadata.getSessionKey());
            System.out.println(msg);
            // CHECKSTYLE:ON
            fail();
        }
    }

    @ParameterizedTest
    @MethodSource("resultOfDecryptionIsCRLFEncodedArguments")
    public void resultOfDecryptionIsCRLFEncoded(String before, String after) throws PGPException, IOException {
        String encrypted = encryptAndSign(before, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.TEXT, true);

        ByteArrayInputStream in = new ByteArrayInputStream(encrypted.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKeys, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCert(publicKeys));

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, decrypted);
        decryptionStream.close();

        assertArrayEquals(after.getBytes(StandardCharsets.UTF_8), decrypted.toByteArray());
    }

    private static Stream<Arguments> resultOfDecryptionIsCRLFEncodedArguments() {
        return Stream.of(
                Arguments.of("foo", "foo"),
                Arguments.of("rrr", "rrr"),
                Arguments.of("Foo\nBar!\n", "Foo\r\nBar!\r\n"),
                Arguments.of("Foo\rBar!\r", "Foo\r\nBar!\r\n"),
                Arguments.of("Foo\r\nBar!\r\n", "Foo\r\nBar!\r\n")
        );
    }

    @Test
    public void resultOfDecryptionIsNotCRLFEncoded() throws PGPException, IOException {
        String beforeAndAfter = "Foo\nBar!\n";

        String encrypted = encryptAndSign(beforeAndAfter, DocumentSignatureType.BINARY_DOCUMENT, StreamEncoding.TEXT, false);

        ByteArrayInputStream in = new ByteArrayInputStream(encrypted.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKeys, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCert(publicKeys));

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, decrypted);
        decryptionStream.close();

        assertArrayEquals(beforeAndAfter.getBytes(StandardCharsets.UTF_8), decrypted.toByteArray());
    }

    private String encryptAndSign(String message,
                                  DocumentSignatureType sigType,
                                  StreamEncoding dataFormat,
                                  boolean applyCRLFEncoding)
            throws PGPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ProducerOptions options = ProducerOptions
                .signAndEncrypt(
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(publicKeys),
                        SigningOptions.get()
                                .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, sigType)
                )
                .setEncoding(dataFormat);
        if (applyCRLFEncoding) {
            options.applyCRLFEncoding();
        }

        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(options);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        Streams.pipeAll(inputStream, encryptionStream);
        encryptionStream.close();

        String msg = out.toString();
        return msg;
    }

    private MessageMetadata decryptAndVerify(String msg) throws PGPException, IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKeys, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCert(publicKeys));

        Streams.drain(decryptionStream);
        decryptionStream.close();

        return decryptionStream.getMetadata();
    }

    @Test
    public void testManualSignWithAllCombinations() throws PGPException, IOException {
        for (StreamEncoding streamEncoding : StreamEncoding.values()) {
            for (DocumentSignatureType sigType : DocumentSignatureType.values()) {
                manualSignAndVerify(sigType, streamEncoding);
            }
        }
    }

    public void manualSignAndVerify(DocumentSignatureType sigType, StreamEncoding streamEncoding)
            throws IOException, PGPException {
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);

        PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB);
        OutputStream compressedOut = compressor.open(armorOut);

        PGPSignatureGenerator signer = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(
                        secretKeys.getPublicKey().getAlgorithm(),
                        HashAlgorithm.SHA256.getAlgorithmId()));
        signer.init(sigType.getSignatureType().getCode(), privateKey);

        PGPOnePassSignature ops = signer.generateOnePassVersion(false);
        ops.encode(compressedOut);

        PGPLiteralDataGenerator author = new PGPLiteralDataGenerator();
        OutputStream literalOut = author.open(compressedOut, streamEncoding.getCode(), "", PGPLiteralData.NOW, new byte[4096]);

        byte[] msg = message.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream crlfed = new ByteArrayOutputStream();
        CRLFGeneratorStream crlfOut = new CRLFGeneratorStream(crlfed, streamEncoding);
        crlfOut.write(msg);
        msg = crlfed.toByteArray();

        for (byte b : msg) {
            literalOut.write(b);
            signer.update(b);
        }

        literalOut.close();
        PGPSignature signature = signer.generate();

        signature.encode(compressedOut);
        compressor.close();

        armorOut.close();

        String ciphertext = out.toString();
        // CHECKSTYLE:OFF
        System.out.println(sigType + " " + streamEncoding);
        System.out.println(ciphertext);
        // CHECKSTYLE:ON

        ByteArrayInputStream cipherIn = new ByteArrayInputStream(ciphertext.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                        .onInputStream(cipherIn)
                                .withOptions(new ConsumerOptions()
                                        .addVerificationCert(publicKeys));

        Streams.pipeAll(decryptionStream, decrypted);
        decryptionStream.close();
        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isVerifiedSigned(), "Not verified! Sig Type: " + sigType + " StreamEncoding: " + streamEncoding);

        assertArrayEquals(msg, decrypted.toByteArray());
    }
}
