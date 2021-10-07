// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.util.KeyRingUtils;

public class DecryptAndVerifyMessageTest {

    // Don't use StandardCharsets.UTF8 because of Android API level.
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private PGPSecretKeyRing juliet;
    private PGPSecretKeyRing romeo;

    @BeforeEach
    public void loadKeys() throws IOException, PGPException {
        juliet = TestKeys.getJulietSecretKeyRing();
        romeo = TestKeys.getRomeoSecretKeyRing();
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void decryptMessageAndVerifySignatureTest(ImplementationFactory implementationFactory) throws Exception {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        String encryptedMessage = TestKeys.MSG_SIGN_CRYPT_JULIET_JULIET;

        ConsumerOptions options = new ConsumerOptions()
                .addDecryptionKey(juliet)
                .addVerificationCert(KeyRingUtils.publicKeyRingFrom(juliet));

        DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .withOptions(options);

        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();
        toPlain.close();
        OpenPgpMetadata metadata = decryptor.getResult();

        byte[] expected = TestKeys.TEST_MESSAGE_01_PLAIN.getBytes(UTF8);
        byte[] actual = toPlain.toByteArray();

        assertArrayEquals(expected, actual);

        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isSigned());
        assertTrue(metadata.isVerified());
        assertEquals(CompressionAlgorithm.ZLIB, metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getSymmetricKeyAlgorithm());
        assertEquals(1, metadata.getSignatures().size());
        assertEquals(1, metadata.getVerifiedSignatures().size());
        assertTrue(metadata.containsVerifiedSignatureFrom(TestKeys.JULIET_FINGERPRINT));
        assertEquals(new SubkeyIdentifier(TestKeys.JULIET_FINGERPRINT), metadata.getDecryptionKey());
    }
}
