/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

public class TestKeysTest {

    private final PGPSecretKeyRing juliet;
    private final PGPSecretKeyRing romeo;

    public TestKeysTest() throws IOException, PGPException {
        this.juliet = TestKeys.getJulietSecretKeyRing();
        this.romeo = TestKeys.getRomeoSecretKeyRing();
    }

    @Test
    public void julietKeyTest() {
        assertEquals(TestKeys.JULIET_KEY_ID, juliet.getSecretKey().getKeyID());
        assertEquals(TestKeys.JULIET_FINGERPRINT, new OpenPgpV4Fingerprint(juliet));
        assertEquals(TestKeys.JULIET_FINGERPRINT, new OpenPgpV4Fingerprint(juliet.getPublicKey()));
        assertEquals(TestKeys.JULIET_FINGERPRINT, new OpenPgpV4Fingerprint(juliet.getSecretKey()));
        assertEquals(TestKeys.JULIET_KEY_ID, TestKeys.JULIET_FINGERPRINT.getKeyId());
    }

    @Test
    public void romeoKeyTest() {
        assertEquals(TestKeys.ROMEO_KEY_ID, romeo.getSecretKey().getKeyID());
        assertEquals(TestKeys.ROMEO_FINGERPRINT, new OpenPgpV4Fingerprint(romeo));
        assertEquals(TestKeys.ROMEO_FINGERPRINT, new OpenPgpV4Fingerprint(romeo.getPublicKey()));
        assertEquals(TestKeys.ROMEO_FINGERPRINT, new OpenPgpV4Fingerprint(romeo.getSecretKey()));
        assertEquals(TestKeys.ROMEO_KEY_ID, TestKeys.ROMEO_FINGERPRINT.getKeyId());
    }

    @Test
    public void decryptVerifyTest() throws Exception {
        String encryptedMessage = TestKeys.MSG_SIGN_CRYPT_JULIET_JULIET;

        DecryptionStream decryptor = PGPainless.createDecryptor()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .decryptWith(new UnprotectedKeysProtector(), new PGPSecretKeyRingCollection(Collections.singleton(juliet)))
                .verifyWith(Collections.singleton(new PGPPublicKeyRing(Collections.singletonList(juliet.getPublicKey()))))
                .ignoreMissingPublicKeys()
                .build();

        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();
        toPlain.close();
        OpenPgpMetadata metadata = decryptor.getResult();

        byte[] expected = TestKeys.TEST_MESSAGE_01_PLAIN.getBytes(StandardCharsets.UTF_8);
        byte[] actual = toPlain.toByteArray();

        assertArrayEquals(expected, actual);

        assertTrue(metadata.isIntegrityProtected());
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isSigned());
        assertTrue(metadata.isVerified());
        assertEquals(CompressionAlgorithm.ZLIB, metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getSymmetricKeyAlgorithm());
        assertEquals(1, metadata.getSignatureKeyIDs().size());
        assertEquals(1, metadata.getVerifiedSignatureKeyFingerprints().size());
        assertTrue(metadata.containsVerifiedSignatureFrom(TestKeys.JULIET_FINGERPRINT));
        assertEquals(TestKeys.JULIET_FINGERPRINT, metadata.getDecryptionFingerprint());

    }
}
