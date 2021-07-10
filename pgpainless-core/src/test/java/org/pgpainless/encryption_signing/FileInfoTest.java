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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.util.KeyRingUtils;

public class FileInfoTest {

    @Test
    public void textFile() throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException, IOException {
        OpenPgpMetadata.FileInfo fileInfo = new OpenPgpMetadata.FileInfo("message.txt", new Date(), StreamEncoding.TEXT);
        executeWith(fileInfo);
    }

    @Test
    public void binaryStream() throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException, IOException {
        OpenPgpMetadata.FileInfo fileInfo = OpenPgpMetadata.FileInfo.binaryStream();
        executeWith(fileInfo);
    }

    @Test
    public void forYourEyesOnly() throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException, IOException {
        OpenPgpMetadata.FileInfo fileInfo = OpenPgpMetadata.FileInfo.forYourEyesOnly();
        executeWith(fileInfo);
    }

    public void executeWith(OpenPgpMetadata.FileInfo fileInfo) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        String data = "Hello, World!";

        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(dataOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions
                                .encryptCommunications()
                                .addRecipient(publicKeys))
                        .setEncoding(fileInfo.getStreamFormat())
                        .setFileName(fileInfo.getFileName())
                        .setModificationDate(fileInfo.getModificationDate())
                );

        Streams.pipeAll(dataIn, encryptionStream);
        encryptionStream.close();

        OpenPgpMetadata.FileInfo cryptInfo = encryptionStream.getResult().getFileInfo();
        assertEquals(fileInfo, cryptInfo);

        ByteArrayInputStream cryptIn = new ByteArrayInputStream(dataOut.toByteArray());
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKeys));
        Streams.pipeAll(decryptionStream, plainOut);

        decryptionStream.close();

        OpenPgpMetadata.FileInfo decryptInfo = decryptionStream.getResult().getFileInfo();
        assertEquals(fileInfo, decryptInfo);
    }
}
