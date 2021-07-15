/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.JUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;

public class FileInformationTest {

    private static final String data = "Hello, World!\n";
    private static PGPSecretKeyRing secretKey;
    private static PGPPublicKeyRing certificate;

    @BeforeAll
    public static void generateKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        secretKey = PGPainless.generateKeyRing().modernKeyRing("alice@wonderland.lit", null);
        certificate = PGPainless.extractCertificate(secretKey);
    }

    @Test
    public void testTextFile() throws PGPException, IOException {
        String fileName = "message.txt";
        Date modificationDate = new Date();
        StreamEncoding encoding = StreamEncoding.TEXT;

        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications()
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
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKey));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        OpenPgpMetadata decResult = decryptionStream.getResult();

        assertEquals(fileName, decResult.getFileName());
        JUtils.assertDateEquals(modificationDate, decResult.getModificationDate());
        assertEquals(encoding, decResult.getFileEncoding());
    }

    @Test
    public void testDefaults() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications()
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
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKey));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        OpenPgpMetadata decResult = decryptionStream.getResult();

        assertEquals("", decResult.getFileName());
        JUtils.assertDateEquals(PGPLiteralData.NOW, decResult.getModificationDate());
        assertEquals(PGPLiteralData.BINARY, decResult.getFileEncoding().getCode());
        assertFalse(decResult.isForYourEyesOnly());
    }

    @Test
    public void testForYourEyesOnly() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications()
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
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKey));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        OpenPgpMetadata decResult = decryptionStream.getResult();

        assertEquals(PGPLiteralData.CONSOLE, decResult.getFileName());
        JUtils.assertDateEquals(PGPLiteralData.NOW, decResult.getModificationDate());
        assertEquals(PGPLiteralData.BINARY, decResult.getFileEncoding().getCode());
        assertTrue(decResult.isForYourEyesOnly());
    }
}
