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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
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
            "hF4Dyqa/GWUy6WsSAQdAQ62BwmUt8Iby0+jvrLhMgST79KR/as+dyl0nf1uki2sw\n" +
            "Thg1Ojtf0hOyJgcpQ4nP2Q0wYFR0F1sCydaIlTGreYZHlGtybP7/Ml6KNZILTRWP\n" +
            "0kYBkGBgK7oQWRIVyoF2POvEP6EX1X8nvQk7O3NysVdRVbnia7gE3AzRYuha4kxs\n" +
            "pI6xJkntLMS3K6him1Y9FHINIASFSB+C\n" +
            "=5p00\n" +
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
        // genPENC_COMP_LIT();
        genOPS_LIT_SIG();
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

    public static void genKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPainless.asciiArmor(
                PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>"),
                System.out);
    }

    public static void genSIG_LIT() throws PGPException, IOException {
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
                                .addPassphrase(Passphrase.fromPassword(PASSPHRASE)))
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
        assertEquals(StreamEncoding.BINARY, metadata.getFormat());
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
    }

    @ParameterizedTest(name = "Process SENC(LIT) using {0}")
    @MethodSource("provideMessageProcessors")
    public void testProcessSENC_LIT(Processor processor)
            throws PGPException, IOException {
        Tuple<String, MessageMetadata> result = processor.process(SENC_LIT, ConsumerOptions.get()
                .addDecryptionPassphrase(Passphrase.fromPassword(PASSPHRASE)));
        String plain = result.getA();
        assertEquals(PLAINTEXT, plain);
        MessageMetadata metadata = result.getB();
        assertNull(metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
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
    }

    private static Tuple<String, MessageMetadata> processReadBuffered(String armoredMessage, ConsumerOptions options)
            throws PGPException, IOException {
        OpenPgpMessageInputStream in = get(armoredMessage, options);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(in, out);
        in.close();
        MessageMetadata metadata = in.getMetadata();
        return new Tuple<>(out.toString(), metadata);
    }

    private static Tuple<String, MessageMetadata> processReadSequential(String armoredMessage, ConsumerOptions options)
            throws PGPException, IOException {
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
            throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        OpenPgpMessageInputStream pgpIn = new OpenPgpMessageInputStream(armorIn, options);
        return pgpIn;
    }
}
