// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.JUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;

public class FileInformationTest {

    private static final String data = "Hello, World!\n";
    private static OpenPGPKey secretKey;
    private static OpenPGPCertificate certificate;
    private static final PGPainless api = PGPainless.getInstance();

    @BeforeAll
    public static void generateKey() {
        secretKey = api.generateKey().modernKeyRing("alice@wonderland.lit");
        certificate = secretKey.toCertificate();
    }

    @Test
    public void testTextFile() throws PGPException, IOException {
        String fileName = "message.txt";
        Date modificationDate = new Date();
        StreamEncoding encoding = StreamEncoding.TEXT;

        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        // noinspection deprecation
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications(api)
                                .addRecipient(certificate))
                        .setFileName(fileName)
                        .setModificationDate(modificationDate)
                        .setEncoding(encoding)
                );

        Streams.pipeAll(dataIn, encryptionStream);
        encryptionStream.close();

        EncryptionResult encResult = encryptionStream.getResult();
        assertEquals(fileName, encResult.getFileName());
        JUtils.assertDateEquals(modificationDate, encResult.getModificationDate());
        assertEquals(encoding, encResult.getFileEncoding());

        ByteArrayInputStream cryptIn = new ByteArrayInputStream(dataOut.toByteArray());
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKey));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        MessageMetadata decResult = decryptionStream.getMetadata();

        assertEquals(fileName, decResult.getFilename());
        JUtils.assertDateEquals(modificationDate, decResult.getModificationDate());
        assertEquals(encoding, decResult.getLiteralDataEncoding());
    }

    @Test
    public void testDefaults() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications(api)
                                .addRecipient(certificate))
                );

        Streams.pipeAll(dataIn, encryptionStream);
        encryptionStream.close();

        EncryptionResult encResult = encryptionStream.getResult();
        assertEquals("", encResult.getFileName());
        JUtils.assertDateEquals(PGPLiteralData.NOW, encResult.getModificationDate());
        assertEquals(PGPLiteralData.BINARY, encResult.getFileEncoding().getCode());
        assertFalse(encResult.isForYourEyesOnly());

        ByteArrayInputStream cryptIn = new ByteArrayInputStream(dataOut.toByteArray());
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKey));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        MessageMetadata decResult = decryptionStream.getMetadata();

        assertEquals("", decResult.getFilename());
        JUtils.assertDateEquals(PGPLiteralData.NOW, decResult.getModificationDate());
        assertNotNull(decResult.getLiteralDataEncoding());
        assertEquals(PGPLiteralData.BINARY, decResult.getLiteralDataEncoding().getCode());
        // noinspection deprecation
        assertFalse(decResult.isForYourEyesOnly());
    }

    @Test
    public void testForYourEyesOnly() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        // noinspection deprecation
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications(api)
                                .addRecipient(certificate))
                        .setForYourEyesOnly()
                );

        Streams.pipeAll(dataIn, encryptionStream);
        encryptionStream.close();

        EncryptionResult encResult = encryptionStream.getResult();
        assertEquals(PGPLiteralData.CONSOLE, encResult.getFileName());
        JUtils.assertDateEquals(PGPLiteralData.NOW, encResult.getModificationDate());
        assertEquals(PGPLiteralData.BINARY, encResult.getFileEncoding().getCode());
        assertTrue(encResult.isForYourEyesOnly());

        ByteArrayInputStream cryptIn = new ByteArrayInputStream(dataOut.toByteArray());
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKey));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        MessageMetadata decResult = decryptionStream.getMetadata();

        assertEquals(PGPLiteralData.CONSOLE, decResult.getFilename());
        JUtils.assertDateEquals(PGPLiteralData.NOW, decResult.getModificationDate());
        assertNotNull(decResult.getLiteralDataEncoding());
        assertEquals(PGPLiteralData.BINARY, decResult.getLiteralDataEncoding().getCode());
        // noinspection deprecation
        assertTrue(decResult.isForYourEyesOnly());
    }
}
