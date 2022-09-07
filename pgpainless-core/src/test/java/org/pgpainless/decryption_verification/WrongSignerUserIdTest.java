// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.policy.Policy;
import org.pgpainless.s2k.Passphrase;

public class WrongSignerUserIdTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "   Comment: Alice's OpenPGP Transferable Secret Key\n" +
            "   Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
            "\n" +
            "   lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
            "   b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
            "   ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
            "   CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
            "   nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
            "   a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
            "   BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
            "   /3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
            "   u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
            "   hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
            "   Pnn+We1aTBhaGa86AQ==\n" +
            "   =n8OM\n" +
            "   -----END PGP PRIVATE KEY BLOCK-----";
    private static final String USER_ID = "Alice Lovelace <alice@openpgp.example>";

    @Test
    public void verificationSucceedsWithDisabledCheck() throws PGPException, IOException {
        executeTest(false, true);
    }

    @Test
    public void verificationFailsWithEnabledCheck() throws PGPException, IOException {
        executeTest(true, false);
    }

    @AfterAll
    public static void resetDefault() {
        PGPainless.getPolicy().setSignerUserIdValidationLevel(Policy.SignerUserIdValidationLevel.DISABLED);
    }

    public void executeTest(boolean enableCheck, boolean expectSucessfulVerification) throws IOException, PGPException {
        PGPainless.getPolicy().setSignerUserIdValidationLevel(enableCheck ? Policy.SignerUserIdValidationLevel.STRICT : Policy.SignerUserIdValidationLevel.DISABLED);
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        assertEquals(USER_ID, secretKeys.getPublicKey().getUserIDs().next());

        String messageWithWrongUserId = generateTestMessage(secretKeys);
        verifyTestMessage(messageWithWrongUserId, secretKeys, expectSucessfulVerification);
    }

    private void verifyTestMessage(String messageWithWrongUserId, PGPSecretKeyRing secretKeys, boolean expectSuccessfulVerification) throws IOException, PGPException {
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify().onInputStream(
                        new ByteArrayInputStream(messageWithWrongUserId.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKeys)
                        .addVerificationCert(certificate));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);

        decryptionStream.close();
        OpenPgpMetadata metadata = decryptionStream.getResult();

        if (expectSuccessfulVerification) {
            assertTrue(metadata.isVerified());
        } else {
            assertFalse(metadata.isVerified());
        }

    }

    private String generateTestMessage(PGPSecretKeyRing secretKeys) throws PGPException, IOException {
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);

        assertEquals(USER_ID, certificate.getPublicKey().getUserIDs().next());

        Iterator<PGPSecretKey> keys = secretKeys.getSecretKeys();
        PGPSecretKey signingKey = keys.next();
        PGPSecretKey encryptionKey = keys.next();

        PGPPrivateKey signingPrivKey = UnlockSecretKey.unlockSecretKey(signingKey, Passphrase.emptyPassphrase());

        // ARMOR
        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(cipherText);

        // ENCRYPTION
        PGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        dataEncryptorBuilder.setWithIntegrityPacket(true);

        PGPEncryptedDataGenerator encDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        encDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encryptionKey.getPublicKey()));
        OutputStream encStream = encDataGenerator.open(armorOut, new byte[4096]);

        // COMPRESSION
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB);
        BCPGOutputStream bOut = new BCPGOutputStream(compressedDataGenerator.open(encStream));

        // SIGNING
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signingKey.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()));
        sigGen.init(PGPSignature.BINARY_DOCUMENT, signingPrivKey);

        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.addSignerUserID(false, "Albert Lovelace <albert@openpgp.example>");
        sigGen.setHashedSubpackets(subpacketGenerator.generate());

        sigGen.generateOnePassVersion(false).encode(bOut);

        // LITERAL DATA
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream lOut = literalDataGenerator.open(bOut, PGPLiteralDataGenerator.BINARY,
                PGPLiteralDataGenerator.CONSOLE, new Date(), new byte[4096]);

        // write msg
        ByteArrayInputStream msgIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        int ch;
        while ((ch = msgIn.read()) >= 0) {
            lOut.write(ch);
            sigGen.update((byte) ch);
        }

        lOut.close();
        sigGen.generate().encode(bOut);
        compressedDataGenerator.close();
        encStream.close();
        armorOut.close();

        return cipherText.toString();
    }
}
