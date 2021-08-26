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
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.signature.CertificateValidator;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.SignatureVerifier;
import org.pgpainless.signature.cleartext_signatures.CleartextSignatureProcessor;
import org.pgpainless.signature.cleartext_signatures.InMemoryMultiPassStrategy;
import org.pgpainless.signature.cleartext_signatures.MultiPassStrategy;
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

    @Test
    public void cleartextSignVerification_InMemoryMultiPassStrategy() throws IOException, PGPException {
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();

        InMemoryMultiPassStrategy multiPassStrategy = MultiPassStrategy.keepMessageInMemory();
        CleartextSignatureProcessor processor = PGPainless.verifyCleartextSignedMessage()
                .onInputStream(new ByteArrayInputStream(MESSAGE_SIGNED))
                .withStrategy(multiPassStrategy)
                .verifyWith(signingKeys);

        PGPSignature signature = processor.process();

        assertEquals(signature.getKeyID(), signingKeys.getPublicKey().getKeyID());
        assertArrayEquals(MESSAGE_BODY, multiPassStrategy.getBytes());
    }

    @Test
    public void cleartextSignVerification_FileBasedMultiPassStrategy() throws IOException, PGPException {
        PGPPublicKeyRing signingKeys = TestKeys.getEmilPublicKeyRing();

        File tempDir = TestUtils.createTempDirectory();
        File file = new File(tempDir, "file");
        MultiPassStrategy multiPassStrategy = MultiPassStrategy.writeMessageToFile(file);
        CleartextSignatureProcessor processor = PGPainless.verifyCleartextSignedMessage()
                .onInputStream(new ByteArrayInputStream(MESSAGE_SIGNED))
                .withStrategy(multiPassStrategy)
                .verifyWith(signingKeys);

        PGPSignature signature = processor.process();

        assertEquals(signature.getKeyID(), signingKeys.getPublicKey().getKeyID());
        FileInputStream fileIn = new FileInputStream(file);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        Streams.pipeAll(fileIn, bytes);
        fileIn.close();
        assertArrayEquals(MESSAGE_BODY, bytes.toByteArray());
    }

    @Test
    public void verifySignatureDetached() throws IOException, PGPException {
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
    public void testOutputOfSigVerification() throws IOException, PGPException {
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
}
