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
package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.signature.cleartext_signatures.CleartextSignatureProcessor;
import org.pgpainless.signature.cleartext_signatures.InMemoryMultiPassStrategy;
import org.pgpainless.signature.cleartext_signatures.MultiPassStrategy;
import org.pgpainless.util.StreamUtil;
import org.pgpainless.util.TestUtils;

public class CleartextSignatureVerificationTest {

    @Test
    public void cleartextSignVerification_InMemoryMultiPassStrategy() throws IOException, PGPException {
        String message = "Ah, Juliet, if the measure of thy joy\n" +
                "Be heaped like mine, and that thy skill be more\n" +
                "To blazon it, then sweeten with thy breath\n" +
                "This neighbor air, and let rich music’s tongue\n" +
                "Unfold the imagined happiness that both\n" +
                "Receive in either by this dear encounter.\n";
        String signed = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
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
                "-----END PGP SIGNATURE-----";
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();

        InMemoryMultiPassStrategy multiPassStrategy = MultiPassStrategy.keepMessageInMemory();
        CleartextSignatureProcessor processor = PGPainless.verifyCleartextSignedMessage()
                .onInputStream(new ByteArrayInputStream(signed.getBytes(StandardCharsets.UTF_8)))
                .withStrategy(multiPassStrategy)
                .verifyWith(signingKeys);

        PGPSignature signature = processor.process();

        assertEquals(signature.getKeyID(), signingKeys.getPublicKey().getKeyID());
        assertArrayEquals(message.getBytes(StandardCharsets.UTF_8), multiPassStrategy.getBytes());
    }

    @Test
    public void cleartextSignVerification_FileBasedMultiPassStrategy() throws IOException, PGPException {
        String message = "Ah, Juliet, if the measure of thy joy\n" +
                "Be heaped like mine, and that thy skill be more\n" +
                "To blazon it, then sweeten with thy breath\n" +
                "This neighbor air, and let rich music’s tongue\n" +
                "Unfold the imagined happiness that both\n" +
                "Receive in either by this dear encounter.\n";
        String signed = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
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
                "-----END PGP SIGNATURE-----";
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();

        File tempDir = TestUtils.createTempDirectory();
        File file = new File(tempDir, "file");
        MultiPassStrategy multiPassStrategy = MultiPassStrategy.writeMessageToFile(file);
        CleartextSignatureProcessor processor = PGPainless.verifyCleartextSignedMessage()
                .onInputStream(new ByteArrayInputStream(signed.getBytes(StandardCharsets.UTF_8)))
                .withStrategy(multiPassStrategy)
                .verifyWith(signingKeys);

        PGPSignature signature = processor.process();

        assertEquals(signature.getKeyID(), signingKeys.getPublicKey().getKeyID());
        FileInputStream fileIn = new FileInputStream(file);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        StreamUtil.pipeAll(fileIn, bytes);
        fileIn.close();
        assertArrayEquals(message.getBytes(StandardCharsets.UTF_8), bytes.toByteArray());
    }
}
