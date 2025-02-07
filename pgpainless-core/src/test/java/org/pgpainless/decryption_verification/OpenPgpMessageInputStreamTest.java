// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Iterator;
import java.util.stream.Stream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.JUtils;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;

public class OpenPgpMessageInputStreamTest {

    public static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: DA05 848F 37D4 68E6 F982  C889 7A70 1FC6 904D 3F4C\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEYxzSCBYJKwYBBAHaRw8BAQdAeJU8m4GOJb1eQgv/ryilFHRfNLTYFMNqL6zj\n" +
            "r0vF7dsAAP42rAtngpJ6dZxoZlJX0Je65zk1VMPeTrXaWfPS2HSKBRGptBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmMc0ggJEHpwH8aQTT9M\n" +
            "FiEE2gWEjzfUaOb5gsiJenAfxpBNP0wCngECmwEFFgIDAQAECwkIBwUVCgkICwKZ\n" +
            "AQAApZEBALUXHtvswPZG28YO+16Men6/fpk+scvqpNMnD4ty3IkAAPwK6TuXjNnZ\n" +
            "0XuWdnilvLMV23Ai1d5g6em+lwLK5M2SApxdBGMc0ggSCisGAQQBl1UBBQEBB0D8\n" +
            "mNUVX8y2MXFaSeFYqOTPFnGT7dgNVdn6yc0UtkkHOgMBCAcAAP9y9OtP4SX9voPb\n" +
            "ID2u9PkJKgo4hTB8NK5LouGppdRtEBGriHUEGBYKAB0FAmMc0ggCngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRB6cB/GkE0/TAywAQDpZRJS/joFH4+xcwheqWfI7ay/\n" +
            "WfojUoGQMYGnUjsgYwEAkceRUsgkqI0SVgYvuglfaQpZ9k2ns1mZGVLkXvu/yQyc\n" +
            "WARjHNIIFgkrBgEEAdpHDwEBB0BGN9BybSOrj8B6gim1SjbB/IiqAshlzMDunVkQ\n" +
            "X23npQABAJqvjOOY7qhBuTusC5/Q5+25iLrhMn4TI+LXlJHMVNOaE0OI1QQYFgoA\n" +
            "fQUCYxzSCAKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmMc0ggACgkQ\n" +
            "KALh4BJQXl6yTQD/dh0N5228Uwtu7XHy6dmpMRX62cac5tXQ9WaDzpy8STgBAMdn\n" +
            "Mq948UOYEhdk/ZY2/hwux/4t+FHvqrXW8ziBe4cLAAoJEHpwH8aQTT9M1hQA/3Ms\n" +
            "P3kzoed3VsWu1ZMr7dKEngbc6SoJ2XPayzN0QYJaAQCIY5NcT9mZF97HWV3Vgeum\n" +
            "00sWMHXfkW3+nl5OpUZaDA==\n" +
            "=THgv\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String PLAINTEXT = "Hello, World!\n";
    public static final String PASSPHRASE = "sw0rdf1sh";

    public static final String LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "yxRiAAAAAABIZWxsbywgV29ybGQhCg==\n" +
            "=WGju\n" +
            "-----END PGP MESSAGE-----";

    public static final String LIT_LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "yxRiAAAAAABIZWxsbywgV29ybGQhCssUYgAAAAAASGVsbG8sIFdvcmxkIQo=\n" +
            "=A91Q\n" +
            "-----END PGP MESSAGE-----";

    public static final String COMP_LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "owE7LZLEAAIeqTk5+ToK4flFOSmKXAA=\n" +
            "=ZYDg\n" +
            "-----END PGP MESSAGE-----";

    public static final String COMP = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "owEDAA==\n" +
            "=MDzg\n" +
            "-----END PGP MESSAGE-----";

    public static final String COMP_COMP_LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "owEBRwC4/6MDQlpoOTFBWSZTWVuW2KAAAAr3hGAQBABgBABAAIAWBJAAAAggADFM\n" +
            "ABNBqBo00N6puqWR+TqInoXQ58XckU4UJBbltigA\n" +
            "=K9Zl\n" +
            "-----END PGP MESSAGE-----";

    public static final String SIG_COMP_LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "iHUEABYKACcFAmMc1i0JECgC4eASUF5eFiEEjN3RiJxCf/TyYOQjKALh4BJQXl4A\n" +
            "AHkrAP98uPpqrgIix7epgL7MM1cjXXGSxqbDfXHwgptk1YGQlgD/fw89VGcXwFaI\n" +
            "2k7kpXQYy/1BqnovM/jZ3X3mXhhTaAOjATstksQAAh6pOTn5Ogrh+UU5KYpcAA==\n" +
            "=WKPn\n" +
            "-----END PGP MESSAGE-----";

    public static final String SENC_LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "jA0ECQMCuZ0qHNXWnGhg0j8Bdm1cxV65sYb7jDgb4rRMtdNpQ1dC4UpSYuk9YWS2\n" +
            "DpNEijbX8b/P1UOK2kJczNDADMRegZuLEI+dNsBnJjk=\n" +
            "=i4Y0\n" +
            "-----END PGP MESSAGE-----";

    public static final String PENC_COMP_LIT = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4Dyqa/GWUy6WsSAQdAuGt49sQwdAHH3jPx11V3wSh7Amur3TbnONiQYJmMo3Qw\n" +
            "87yBnZCsaB7evxLBgi6PpF3tiytHM60xlrPeKKPpJhu60vNafRM2OOwqk7AdcZw4\n" +
            "0kYBEhiioO2btSuafNrQEjYzAgC7K6l7aPCcQObNp4ofryXu1P5vN+vUZp357hyS\n" +
            "6zZqP+0wJQ9yJZMvFTtFeSaSi0oMP2sb\n" +
            "=LvRL\n" +
            "-----END PGP MESSAGE-----";

    public static final String OPS_LIT_SIG = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "kA0DAAoWKALh4BJQXl4ByxRiAAAAAABIZWxsbywgV29ybGQhCoh1BAAWCgAnBQJj\n" +
            "I3fSCRAoAuHgElBeXhYhBIzd0YicQn/08mDkIygC4eASUF5eAADLOgEA766VyMMv\n" +
            "sxfQwQHly3T6ySHSNhYEpoyvdxVqhjBBR+EA/3i6C8lKFPPTh/PvTGbVFOl+eUSV\n" +
            "I0w3c+BRY/pO0m4H\n" +
            "=tkTV\n" +
            "-----END PGP MESSAGE-----";

    public static void main(String[] args) throws Exception {
        // genLIT();
        // genLIT_LIT();
        // genCOMP_LIT();
        // genCOMP();
        // genCOMP_COMP_LIT();
        // genKey();
        // genSIG_LIT();
        // genSENC_LIT();
        genPENC_COMP_LIT();
        // genOPS_LIT_SIG();
    }

    public static void genLIT() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(armorOut, PGPLiteralDataGenerator.BINARY, "", PGPLiteralData.NOW, new byte[1 << 9]);
        litOut.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        litOut.close();
        armorOut.close();
    }

    public static void genLIT_LIT() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(armorOut, PGPLiteralDataGenerator.BINARY, "", PGPLiteralData.NOW, new byte[1 << 9]);
        litOut.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        litOut.close();

        litOut = litGen.open(armorOut, PGPLiteralDataGenerator.BINARY, "", PGPLiteralData.NOW, new byte[1 << 9]);
        litOut.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        litOut.close();

        armorOut.close();
    }

    public static void genCOMP_LIT() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);
        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compOut = compGen.open(armorOut);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(compOut, PGPLiteralDataGenerator.BINARY, "", PGPLiteralData.NOW, new byte[1 << 9]);
        litOut.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        litOut.close();
        compOut.close();
        armorOut.close();
    }

    public static void genCOMP() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);
        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compOut = compGen.open(armorOut);
        compOut.close();
        armorOut.close();
    }

    public static void genCOMP_COMP_LIT() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);

        PGPCompressedDataGenerator compGen1 = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compOut1 = compGen1.open(armorOut);

        PGPCompressedDataGenerator compGen2 = new PGPCompressedDataGenerator(CompressionAlgorithmTags.BZIP2);
        OutputStream compOut2 = compGen2.open(compOut1);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(compOut2, PGPLiteralDataGenerator.BINARY, "", PGPLiteralDataGenerator.NOW, new byte[1 << 9]);

        litOut.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        litOut.close();
        compOut2.close();
        compOut1.close();
        armorOut.close();
    }

    public static void genKey() {
        PGPainless.asciiArmor(
                PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>"),
                System.out);
    }

    public static void genSIG_COMP_LIT() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();
        EncryptionStream signer = PGPainless.encryptAndOrSign()
                .onOutputStream(msgOut)
                .withOptions(
                        ProducerOptions.sign(
                                SigningOptions.get()
                                        .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys)
                        ).setAsciiArmor(false)
                );

        Streams.pipeAll(new ByteArrayInputStream(PLAINTEXT.getBytes(StandardCharsets.UTF_8)), signer);
        signer.close();
        EncryptionResult result = signer.getResult();
        PGPSignature detachedSignature = result.getDetachedSignatures().get(result.getDetachedSignatures().keySet().iterator().next()).iterator().next();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        armorOut.flush();
        detachedSignature.encode(armorOut);
        armorOut.write(msgOut.toByteArray());
        armorOut.close();

        String armored = out.toString();
        // CHECKSTYLE:OFF
        System.out.println(armored
                .replace("-----BEGIN PGP SIGNATURE-----\n", "-----BEGIN PGP MESSAGE-----\n")
                .replace("-----END PGP SIGNATURE-----", "-----END PGP MESSAGE-----"));
        // CHECKSTYLE:ON
    }

    public static void genSENC_LIT() throws PGPException, IOException {
        EncryptionStream enc = PGPainless.encryptAndOrSign()
                .onOutputStream(System.out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.get()
                                .addMessagePassphrase(Passphrase.fromPassword(PASSPHRASE)))
                        .overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED));
        enc.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        enc.close();
    }

    public static void genPENC_COMP_LIT() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        PGPPublicKeyRing cert = PGPainless.extractCertificate(secretKeys);
        EncryptionStream enc = PGPainless.encryptAndOrSign()
                .onOutputStream(System.out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.get()
                                .addRecipient(cert))
                        .overrideCompressionAlgorithm(CompressionAlgorithm.ZLIB));

        Streams.pipeAll(new ByteArrayInputStream(PLAINTEXT.getBytes(StandardCharsets.UTF_8)), enc);
        enc.close();
    }

    public static void genOPS_LIT_SIG() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);

        EncryptionStream enc = PGPainless.encryptAndOrSign()
                .onOutputStream(System.out)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                        .addSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys))
                        .overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED));
        Streams.pipeAll(new ByteArrayInputStream(PLAINTEXT.getBytes(StandardCharsets.UTF_8)), enc);
        enc.close();
    }

    interface Processor {
        Tuple<String, MessageMetadata> process(String armoredMessage, ConsumerOptions options) throws PGPException, IOException;
    }

    private static Stream<Arguments> provideMessageProcessors() {
        return Stream.of(
                Arguments.of(Named.of("read(buf,off,len)", (Processor) OpenPgpMessageInputStreamTest::processReadBuffered)),
                Arguments.of(Named.of("read()", (Processor) OpenPgpMessageInputStreamTest::processReadSequential))
        );
    }

    @ParameterizedTest(name = "Process LIT using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessLIT(Processor processor) throws IOException, PGPException {
        Tuple<String, MessageMetadata> result = processor.process(LIT, ConsumerOptions.get());
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);

        MessageMetadata metadata = result.getB();
        assertNull(metadata.getCompressionAlgorithm());
        assertNull(metadata.getEncryptionAlgorithm());
        assertEquals("", metadata.getFilename());
        JUtils.assertDateEquals(new Date(0L), metadata.getModificationDate());
        assertEquals(StreamEncoding.BINARY, metadata.getLiteralDataEncoding());
        assertTrue(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process LIT LIT using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessLIT_LIT_fails(Processor processor) {
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> processor.process(LIT_LIT, ConsumerOptions.get()));
    }

    @ParameterizedTest(name = "Process COMP(LIT) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessCOMP_LIT(Processor processor)
            throws PGPException, IOException {
        Tuple<String, MessageMetadata> result = processor.process(COMP_LIT, ConsumerOptions.get());
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertEquals(CompressionAlgorithm.ZIP, metadata.getCompressionAlgorithm());
        assertTrue(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process COMP using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessCOMP_fails(Processor processor) {
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> processor.process(COMP, ConsumerOptions.get()));
    }

    @ParameterizedTest(name = "Process COMP(COMP(LIT)) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessCOMP_COMP_LIT(Processor processor)
            throws PGPException, IOException {
        Tuple<String, MessageMetadata> result = processor.process(COMP_COMP_LIT, ConsumerOptions.get());
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertEquals(CompressionAlgorithm.ZIP, metadata.getCompressionAlgorithm());
        Iterator<CompressionAlgorithm> compressionAlgorithms = metadata.getCompressionAlgorithms();
        assertEquals(CompressionAlgorithm.ZIP, compressionAlgorithms.next());
        assertEquals(CompressionAlgorithm.BZIP2, compressionAlgorithms.next());
        assertFalse(compressionAlgorithms.hasNext());
        assertNull(metadata.getEncryptionAlgorithm());
        assertTrue(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process SIG COMP(LIT) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessSIG_COMP_LIT(Processor processor)
            throws PGPException, IOException {
        PGPPublicKeyRing cert = PGPainless.extractCertificate(
                PGPainless.readKeyRing().secretKeyRing(KEY));

        Tuple<String, MessageMetadata> result = processor.process(SIG_COMP_LIT, ConsumerOptions.get()
                .addVerificationCert(cert));
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertEquals(CompressionAlgorithm.ZIP, metadata.getCompressionAlgorithm());
        assertNull(metadata.getEncryptionAlgorithm());
        assertFalse(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process SENC(LIT) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessSENC_LIT(Processor processor)
            throws PGPException, IOException {
        Tuple<String, MessageMetadata> result = processor.process(SENC_LIT, ConsumerOptions.get()
                .addMessagePassphrase(Passphrase.fromPassword(PASSPHRASE)));
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertNull(metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
        assertTrue(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process PENC(COMP(LIT)) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessPENC_COMP_LIT(Processor processor)
            throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        Tuple<String, MessageMetadata> result = processor.process(PENC_COMP_LIT, ConsumerOptions.get()
                .addDecryptionKey(secretKeys));
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertEquals(CompressionAlgorithm.ZLIB, metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
        assertTrue(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process OPS LIT SIG using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessOPS_LIT_SIG(Processor processor)
            throws IOException, PGPException {
        PGPPublicKeyRing cert = PGPainless.extractCertificate(PGPainless.readKeyRing().secretKeyRing(KEY));
        Tuple<String, MessageMetadata> result = processor.process(OPS_LIT_SIG, ConsumerOptions.get()
                .addVerificationCert(cert));
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertNull(metadata.getEncryptionAlgorithm());
        assertNull(metadata.getCompressionAlgorithm());
        assertFalse(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    String BOB_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "=miES\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @ParameterizedTest(name = "Process PENC(OPS OPS LIT SIG SIG) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessPENC_OPS_OPS_LIT_SIG_SIG(Processor processor) throws IOException, PGPException {
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMA3wvqk35PDeyAQv/RhY9sgxMXj1UxumNMOeN+1+c5bB5e3jSrvA93L8yLFqB\n" +
                "uF4MsFnHNgu3bS+/a3Z63MRdgS3wOxaRrvEE3y0Q316rP0OQxj9c2mMPZdHlIxjL\n" +
                "KJMzQ6Ofs4kdtapo7plFqKBEEvnp7rF1hFAPxi0/Z+ekuhhOnWg6dZpAZH+s5Li0\n" +
                "rKUltzFJ0bxPe6LCuwyYnzKnNBJJsQdKwcvX2Ip8+6lTX/DjQR1s5nhIe76GaNcU\n" +
                "OvXITOynDsGgNfAmrqTVfrVgDvOVgvj46UPAwS02uYNNk8pWlcy4iGYIlQBUHD6P\n" +
                "k1ieG7ETWsJvStceFqLQVgSDErAga/YXXAJnNUF3PnOxgOlVewdxDCoEeu+3OdQE\n" +
                "j7hqmTTo3iA5GaTKCOi07NwXoXRhEMN3X6XDI5+ovqzAYaPkITxtqZzoNVKMT5hi\n" +
                "tRKl0qwHbMsfHRCQesDmDPU4MlI7TH2iX2jMPxaepyAI++NMW7H6w8bYEFaE0O9v\n" +
                "tiTL2gcYv4O/pGd3isWb0sOkAdz7HkKDdFCUdVMwP25z6dwhEy+oR/q1Le1CjCE/\n" +
                "kY1bmJCTBmJwf86YGZElxFuvCTUBBX6ChI7+o18fljQE7eIS0GjXkQ1j2zEXxgGy\n" +
                "Lhq7yCr6XEIVUj0x8J4LU2RthtgyToOH7EjLRUbqBG2PZD5K7L7b+ueLSkCfM5Gr\n" +
                "isGbTTj6e+TLy6rXGxlNmNDoojpfp/5rRCxrmqPOjBZrNcio8rG19PfBkaw1IXu9\n" +
                "fV9klsIxQyiOmUIl7sc74tTBwdIq8F6FJ7sJIScSCrzMjy+J+VLaBl1LyKs9cWDr\n" +
                "vUqHvc9diwFWjbtZ8wQn9TQug5X4m6sT+pl+7UALAGWdyI9ySlSvVmVnGROKehkV\n" +
                "5VfRds1ICH9Y4XAD7ylzF4dJ0gadtgwD97HLmfApP9IFD/sC4Oy2fu/ERky3Qqrw\n" +
                "nvxDpFZBAzNiTR5VXlEPH2DeQUL0tyJJtq5InjqJm/F2K6O11Xk/HSm9VP3Bnhbc\n" +
                "djaA7GTTYTq2MjPIDYq+ujPkD/WDp5a/2MIWS10ucgZIcLEwJeU/OY+98W/ogrd5\n" +
                "tg03XkKLcGuK6sGv1iYsOGw1vI6RKAkI1j7YBXb7Twb3Ueq/lcRvutgMx/O5k0L5\n" +
                "+d3kl6XJVQVKneft7C6DEu6boiGQCTtloJFxaJ9POqq6DzTQ5hSGvBNiUuek3HV7\n" +
                "lHH544/ONgCufprT3cUSU0CW9EVbeHq3st3wKwxT5ei8nd8R+TuwaPI3TBSqeV03\n" +
                "9fz5x9U2a22Uh53/qux2vAl8DyZHw7VWTP/Bu3eWHiDBEQIQY9BbRMYc7ueNwPii\n" +
                "EROFOrHikkDr8UPwNC9FmpLd4vmQQfioY1bAuFvDckTrRFRp2ft+8m0oWLuF+3IH\n" +
                "lJ2ph3w62VbIOmG0dxtI626n32NcPwk6shCP/gtW1ixuLr1OpiEe5slt2eNiPoTG\n" +
                "CX5UnxzwUkyJ9KgLr3uFkMUwITCF9d2HbnHRaYqVDbQBpZW0wmgtpkTp2tNTExvp\n" +
                "T2kx8LNHxAYNoSX+OOWvWzimkCO9MUfjpa0i5kVNxHronNcb1hKAU6X/2r2Mt3C4\n" +
                "sv2m08spJBQJWnaa/8paYm+c8JS8oACD9SK/8Y4E1kNM3yEgk8dM2BLHKN3xkyT6\n" +
                "iPXHKKgEHivTdpDa8gY81uoqorRHt5gNPDqL/p2ttFquBbQUtRvDCMkvqif5DADS\n" +
                "wvLnnlOohCnQbFsNtWg5G6UUQ0TYbt6bixHpNcYIuFEJubJOJTuh/paxPgI3xx1q\n" +
                "AdrStz97gowgNanOc+Quyt+zmb5cFQdAPLj76xv/W9zd4N601C1NE6+UhZ6mx/Ut\n" +
                "wboetRk4HNcTRmBci5gjNoqB5oQnyAyqhHL1yiD3YmwwELnRwE8563HrHEpU6ziq\n" +
                "D1pPMF6YBcmSuHp8FubPeef8iGHYEJQscRTIy/sb6YQjgShjE4VXfGJ2vOz3KRfU\n" +
                "s7O7MH2b1YkDPsTDuLoDjBzDRoA+2vi034km9Qdcs3w8+vrydw4=\n" +
                "=mdYs\n" +
                "-----END PGP MESSAGE-----\n";
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(BOB_KEY);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);

        Tuple<String, MessageMetadata> result = processor.process(MSG, ConsumerOptions.get()
                .addVerificationCert(certificate)
                .addDecryptionKey(secretKeys));
        String plain = result.getA();
        assertEquals("encrypt ∘ sign ∘ sign", plain);
        MessageMetadata metadata = result.getB();
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
        assertNull(metadata.getCompressionAlgorithm());
        assertFalse(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @ParameterizedTest(name = "Process PENC(OPS OPS OPS LIT SIG SIG SIG) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessOPS_OPS_OPS_LIT_SIG_SIG_SIG(Processor processor) throws IOException, PGPException {
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMA3wvqk35PDeyAQwA0yaEgydkAMEfl7rDTYVGanLKiFiWIs34mkF+LB8qR5eY\n" +
                "ZRuhodPbX9QjpgOZ8fETPU3DEvzOaR0kMqKAHl7mmP0inydK5vpx0U0JTHIZkNeC\n" +
                "rQbizphG2VA8fUvxZ79bZAe43uguITI2R2EZgEzeq6vCO7Ca4XqK95OADKZoVzS7\n" +
                "0uBSMIgAVumrAj2l1ZOYbiIevx0+xJT2NvsLj7TV3ewBIyUg2f5NujcgEnuhpsMu\n" +
                "wM/k58u4iBLAa8Qr2f8WFvLRwH3btfiT9VlKaW+JvIvU9RuNKhMihNY4PXV1uJfv\n" +
                "kKsarMDlRgeRMUHJitwCQP3CSiT+ATCmfHz5e83qsJjBPC0d8qc1H+WKYZ2TPvWO\n" +
                "egzFLTK73ruhTxGeotr4j6fldriewa/S8R9RHWu+6S3NJ9LNWnt9zUJ85d+f0wY3\n" +
                "GVub3y20Zh1dm8A+hnNvK5EB5JyIEP8SFH2N9Cs2YQJn8X7aWYRuBq4KryQDb20n\n" +
                "l4FAiRk414D2Z7XKDvxO0sW6AclnT0DfBm4jZDWquY8U5QsAOtvmMhHlZYVlGm8s\n" +
                "caqoTx9xMugVzkdWv496nx9kFpMWaNB4KBi5B8MBXOeZchOEFIujH0jeWOXUWgJt\n" +
                "hWfNMJSliYlS6VO9aM3ab5SAPcPiHmCkuXXtWBWtmUyUkbWCrZdgq7b4UfGiwQeI\n" +
                "q584RnwPOnRpUfglalP1UqufbJMyl7CFjEMVkcxhApp/zgFZZj0w8oeh9aGflcYJ\n" +
                "PDvsFoJV0P+VbHlI3FTIg+tJZ73gT/X54Mj5ifUpIZQ/abXSSsgrgnZ4qAjLf8Om\n" +
                "GOly5ITEfxJC5rir1yLyBM4T8YJpra3A+3VJo7x/ZatiOxs40uBB4zILIjs5LlCe\n" +
                "WAhFzGzq+VvV7LD6c03USxuV70LhfCUH6ZRq4iXFSnjOoWr5tvWZgzVAc7fshlad\n" +
                "XZB6lz03jWgNvY66kJK5O6pJ8dftuyihHFY7e44+gQttb+41cYhDmm0Nxxq4PDKW\n" +
                "CvI2ETpnW24792D+ZI7XMEfZhY2LoXGYvCkGt5aeo/dsWHoKa3yDjp5/rc2llEFz\n" +
                "A3P8mznBfaRNVjW/UhpMAUI3/kn2bbw21ogrm0NuwZGWIS5ea7+G8TjbrznIQsTq\n" +
                "VlLhMc7d6gK3hKdDsplX5J90YLA0l1SbQGHqb6GXOsIO2tSRpZWUQIIinYdMDmBG\n" +
                "b1wPdwtXmCtyqJfGs/vwmoZdZ0FnwmcsF+bI7LSUnZMK/Cno/Tcl6kWJtvLtG2eC\n" +
                "pHxD/tsU3DoArpDa/+/DOotq+u0CB6ymGAi/NnkFKUdNs8oEt0eOw27/F1teKSgv\n" +
                "wF4KEcbrHoeSlk/95rtnJYT4IkNA1GSZgYALAMSO2sv7XeBab/jRqM7hyMmzKb3R\n" +
                "uXN+BcDHRA1vdvIEpnTD5/EDon3/mr7xgHctzuK8z30aruQoBHWckIgmibB5LNvV\n" +
                "xvFFPFkke6dxEXbYWwYwrqUSHk74420euGa58jnuXtQIr0X+g+UTJegzOjt96ZJH\n" +
                "l92AHadooL7jYiPX8qxw1sln7k0H+RfWSvEbZ0/xsQ0lxgYwds/Ck6yhOUK8hyRW\n" +
                "OVmz3g1QjdwZUDblypsymO3iFggJ0NNhNlYPKEWmwdfTOMDmtuQS97ewDSv0WgAa\n" +
                "oUx2FjjM4iOKiyKsM5i8a4ju3MziFu1ghOfixBwtHRbQHneF5/E5cFtrYvuOlAvN\n" +
                "80r89YesbBzXzsvheez+bIhm4lTHvBKgcb/RNaseYz/72HVk24GGnisSuc37v+O4\n" +
                "YcLflfi86KuLtYQNtR+QyegfYWYogjbsSocWBEfnPJBgtzAtdAnMkaKWbb6WfT4k\n" +
                "J6KWH/wANNdjE4yXPJhRevn3PqHnQvKHJqef1DZgzQMcXD3BwOPXxzy1GXXJw4Jn\n" +
                "Ma1izl7a+KdbPonCnT59Kg24sl6gJplJRZop/tBqUR/c08kIuEuOB1D+qkeAIv6A\n" +
                "3/uK7l4PvVe7XSjZ12Rfm2S7cY4dQybgW81TWKfCDNNXjSAWGAKtfIO7iojzBTF0\n" +
                "MPfpuAx0sP++qUXZGsxIOKUhlqZpDNboHw89UDjj8txc9p6NbWTy6VJoYTKv07sG\n" +
                "4Umrl5oaX49Ub0GlnwWg/wweCrMXszvZAN58qG0Qt2sjnHy1tUIJ7OajDpWrAEYt\n" +
                "cvGzFvsr/j2k9lXBrgtIfSIWo8oQhXDR1gsBw5AxnCWkX0gQPEjYv+rq5zHxfWrF\n" +
                "IOG3zXyoO8QHU0TwdA3s7XBd1pbtyaX0BksW7ecqa+J2KkbXhUOQwMTpgCIGkcBV\n" +
                "CWf3w6voe6ZPfz4KPR3Zbs9ypV6nbfKjUjjfq7Lms1kOVJqZlJp5hf+ew6hxETHp\n" +
                "0QmdhONHZvl+25z4rOquuBwsBXvFw/V5dlvuusi9VBuTUwh/v9JARSNmql8V054M\n" +
                "o6Strj5Ukn+ejymZqXs9yeA+cgE3FL4hzdrUEUt8IVLxvD/XYuWROQJ7AckmU9GA\n" +
                "xpQxbGcDMV6JzkDihKhiX3D6poccaaaFYv85NNCncsDJrPHrU48PQ4qOyr2sFQa+\n" +
                "sfLYfRv5W60Zj3OyVFlK2JrqCu5sT7tecoxCGPCR0m/IpQYYu99JxN2SFv2vV9HI\n" +
                "R6Vg18KxWerJ4sWGDe1CKeCCARiBGD8eNajf6JRu+K9VWUjmYpiEkK68Xaa4/Q2T\n" +
                "x12WVuyITVU3fCfHp6/0A6wPtJezCvoodqPlw/3fd5eSVYzb5C3v564uhz4=\n" +
                "=JP9T\n" +
                "-----END PGP MESSAGE-----";
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(BOB_KEY);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);

        Tuple<String, MessageMetadata> result = processor.process(MSG, ConsumerOptions.get()
                .addVerificationCert(certificate)
                .addDecryptionKey(secretKeys));
        String plain = result.getA();
        assertEquals("encrypt ∘ sign ∘ sign ∘ sign", plain);
        MessageMetadata metadata = result.getB();
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
        assertNull(metadata.getCompressionAlgorithm());
        assertFalse(metadata.getVerifiedInlineSignatures().isEmpty());
        assertTrue(metadata.getRejectedInlineSignatures().isEmpty());
    }

    @Test
    public void readAfterCloseTest() throws IOException {
        OpenPgpMessageInputStream pgpIn = get(SENC_LIT, ConsumerOptions.get()
                .addMessagePassphrase(Passphrase.fromPassword(PASSPHRASE)));
        Streams.drain(pgpIn); // read all

        byte[] buf = new byte[1024];
        assertEquals(-1, pgpIn.read(buf));
        assertEquals(-1, pgpIn.read());
        assertEquals(-1, pgpIn.read(buf));
        assertEquals(-1, pgpIn.read());

        pgpIn.close();
        pgpIn.getMetadata();
    }

    private static Tuple<String, MessageMetadata> processReadBuffered(String armoredMessage, ConsumerOptions options)
            throws IOException {
        OpenPgpMessageInputStream in = get(armoredMessage, options);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(in, out);
        in.close();
        MessageMetadata metadata = in.getMetadata();
        return new Tuple<>(out.toString(), metadata);
    }

    private static Tuple<String, MessageMetadata> processReadSequential(String armoredMessage, ConsumerOptions options)
            throws IOException {
        OpenPgpMessageInputStream in = get(armoredMessage, options);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int r;
        while ((r = in.read()) != -1) {
            out.write(r);
        }

        in.close();
        MessageMetadata metadata = in.getMetadata();
        return new Tuple<>(out.toString(), metadata);
    }

    private static OpenPgpMessageInputStream get(String armored, ConsumerOptions options)
            throws IOException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        OpenPgpMessageInputStream pgpIn = OpenPgpMessageInputStream.create(armorIn, options);
        return pgpIn;
    }
}
