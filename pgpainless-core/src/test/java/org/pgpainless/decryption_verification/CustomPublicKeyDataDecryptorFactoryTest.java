// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CustomPublicKeyDataDecryptorFactoryTest {

    @Test
    public void testDecryptionWithEmulatedHardwareDecryptionCallback()
            throws PGPException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing().modernKeyRing("Alice");
        PGPPublicKeyRing cert = PGPainless.extractCertificate(secretKey);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        PGPPublicKey encryptionKey = info.getEncryptionSubkeys(EncryptionPurpose.ANY).get(0);

        // Encrypt a test message
        String plaintext = "Hello, World!\n";
        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.get()
                        .addRecipient(cert)));
        encryptionStream.write(plaintext.getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();

        HardwareSecurity.DecryptionCallback hardwareDecryptionCallback = new HardwareSecurity.DecryptionCallback() {
            @Override
            public byte[] decryptSessionKey(long keyId, int keyAlgorithm, byte[] sessionKeyData, int pkeskVersion)
                    throws HardwareSecurity.HardwareSecurityException {
                // Emulate hardware decryption.
                try {
                    PGPSecretKey decryptionKey = secretKey.getSecretKey(encryptionKey.getKeyID());
                    PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(decryptionKey, Passphrase.emptyPassphrase());
                    PublicKeyDataDecryptorFactory internal = new BcPublicKeyDataDecryptorFactory(privateKey);
                    return internal.recoverSessionData(keyAlgorithm, new byte[][] {sessionKeyData}, pkeskVersion);
                } catch (PGPException e) {
                    throw new HardwareSecurity.HardwareSecurityException();
                }
            }
        };

        // Decrypt
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ciphertextOut.toByteArray()))
                .withOptions(ConsumerOptions.get()
                        .addCustomDecryptorFactory(
                                new HardwareSecurity.HardwareDataDecryptorFactory(
                                        new SubkeyIdentifier(cert, encryptionKey.getKeyID()),
                                        hardwareDecryptionCallback)));

        ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, decryptedOut);
        decryptionStream.close();

        assertEquals(plaintext, decryptedOut.toString());
    }
}
