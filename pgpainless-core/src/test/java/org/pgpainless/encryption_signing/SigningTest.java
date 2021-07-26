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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.KeyValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.StreamUtil;

public class SigningTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testEncryptionAndSignatureVerification(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPPublicKeyRing julietKeys = TestKeys.getJulietPublicKeyRing();
        PGPPublicKeyRing romeoKeys = TestKeys.getRomeoPublicKeyRing();

        PGPSecretKeyRing cryptieKeys = TestKeys.getCryptieSecretKeyRing();
        KeyRingInfo cryptieInfo = new KeyRingInfo(cryptieKeys);
        PGPSecretKey cryptieSigningKey = cryptieKeys.getSecretKey(cryptieInfo.getSigningSubkeys().get(0).getKeyID());

        PGPPublicKeyRingCollection keys = new PGPPublicKeyRingCollection(Arrays.asList(julietKeys, romeoKeys));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptDataAtRest()
                                .addRecipients(keys)
                                .addRecipient(KeyRingUtils.publicKeyRingFrom(cryptieKeys)),
                        new SigningOptions()
                                .addInlineSignature(SecretKeyRingProtector.unlockSingleKeyWith(TestKeys.CRYPTIE_PASSPHRASE, cryptieSigningKey),
                                        cryptieKeys, TestKeys.CRYPTIE_UID, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                ).setAsciiArmor(true));

        byte[] messageBytes = "This message is signed and encrypted to Romeo and Juliet.".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream message = new ByteArrayInputStream(messageBytes);

        StreamUtil.pipeAll(message, encryptionStream);
        encryptionStream.close();

        byte[] encrypted = out.toByteArray();
        ByteArrayInputStream cryptIn = new ByteArrayInputStream(encrypted);

        PGPSecretKeyRing romeoSecret = TestKeys.getRomeoSecretKeyRing();
        PGPSecretKeyRing julietSecret = TestKeys.getJulietSecretKeyRing();

        PGPSecretKeyRingCollection secretKeys = new PGPSecretKeyRingCollection(Arrays.asList(romeoSecret, julietSecret));
        PGPPublicKeyRingCollection verificationKeys = new PGPPublicKeyRingCollection(Arrays.asList(KeyRingUtils.publicKeyRingFrom(cryptieKeys), romeoKeys));

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(secretKeys, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCerts(verificationKeys)
                );

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();

        StreamUtil.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isSigned());
        assertTrue(metadata.isVerified());
        assertTrue(metadata.containsVerifiedSignatureFrom(KeyRingUtils.publicKeyRingFrom(cryptieKeys)));
        assertFalse(metadata.containsVerifiedSignatureFrom(julietKeys));
    }

    @Test
    public void testSignWithInvalidUserIdFails() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("alice", "password123");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword("password123"), secretKeys);

        SigningOptions opts = new SigningOptions();
        // "bob" is not a valid user-id
        assertThrows(KeyValidationException.class,
                () -> opts.addInlineSignature(protector, secretKeys, "bob", DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @Test
    public void testSignWithRevokedUserIdFails() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("alice", "password123");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword("password123"), secretKeys);
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("alice", protector)
                .done();

        final PGPSecretKeyRing fSecretKeys = secretKeys;

        SigningOptions opts = new SigningOptions();
        // "alice" has been revoked
        assertThrows(KeyValidationException.class,
                () -> opts.addInlineSignature(protector, fSecretKeys, "alice", DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }
}
