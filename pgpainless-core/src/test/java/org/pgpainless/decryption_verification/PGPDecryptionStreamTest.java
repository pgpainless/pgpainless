package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PGPDecryptionStreamTest {

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

    public static final String SIG_LIT = "" +
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

    @Test
    public void genLIT() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(armorOut, PGPLiteralDataGenerator.BINARY, "", PGPLiteralData.NOW, new byte[1 << 9]);
        litOut.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        litOut.close();
        armorOut.close();
    }

    @Test
    public void processLIT() throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(LIT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, out);
        assertEquals(PLAINTEXT, out.toString());
        armorIn.close();
    }

    @Test
    public void getLIT_LIT() throws IOException {
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

    @Test
    public void processLIT_LIT() throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(LIT_LIT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertThrows(MalformedOpenPgpMessageException.class, () -> Streams.pipeAll(decIn, out));
    }

    @Test
    public void genCOMP_LIT() throws IOException {
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

    @Test
    public void processCOMP_LIT() throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(COMP_LIT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, out);
        decIn.close();
        armorIn.close();

        assertEquals(PLAINTEXT, out.toString());
    }

    @Test
    public void genCOMP() throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(System.out);
        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compOut = compGen.open(armorOut);
        compOut.close();
        armorOut.close();
    }

    @Test
    public void processCOMP() throws IOException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(COMP.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        assertThrows(MalformedOpenPgpMessageException.class, () -> {
            MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get());
            Streams.drain(decIn);
        });
    }

    @Test
    public void genCOMP_COMP_LIT() throws IOException {
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

    @Test
    public void processCOMP_COMP_LIT() throws PGPException, IOException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(COMP_COMP_LIT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, out);
        decIn.close();

        assertEquals(PLAINTEXT, out.toString());
    }

    @Test
    public void genKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        System.out.println(PGPainless.asciiArmor(
                PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>")
        ));
    }

    @Test
    public void genSIG_LIT() throws PGPException, IOException {
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
        System.out.println(armored
                .replace("-----BEGIN PGP SIGNATURE-----\n", "-----BEGIN PGP MESSAGE-----\n")
                .replace("-----END PGP SIGNATURE-----", "-----END PGP MESSAGE-----"));
    }

    @Test
    public void processSIG_LIT() throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(SIG_LIT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, out);
        decIn.close();

        System.out.println(out);
    }

    @Test
    public void genSENC_LIT() throws PGPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream enc = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.get()
                                .addPassphrase(Passphrase.fromPassword(PASSPHRASE)))
                        .overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED));
        enc.write(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        enc.close();

        System.out.println(out);
    }

    @Test
    public void processSENC_LIT() throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(SENC_LIT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        MessageDecryptionStream decIn = new MessageDecryptionStream(armorIn, ConsumerOptions.get()
                .addDecryptionPassphrase(Passphrase.fromPassword(PASSPHRASE)));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, out);
        decIn.close();

        System.out.println(out);
    }
}
