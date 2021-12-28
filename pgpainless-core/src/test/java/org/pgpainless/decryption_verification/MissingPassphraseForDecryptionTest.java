// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.exception.MissingPassphraseException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

public class MissingPassphraseForDecryptionTest {

    private final String passphrase = "dragon123";
    private PGPSecretKeyRing secretKeys;
    private byte[] message;

    @BeforeEach
    public void setup() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        secretKeys = PGPainless.generateKeyRing().modernKeyRing("Test", passphrase);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.encryptCommunications()
                        .addRecipient(certificate)));

        Streams.pipeAll(new ByteArrayInputStream("Hey, what's up?".getBytes(StandardCharsets.UTF_8)), encryptionStream);
        encryptionStream.close();
        message = out.toByteArray();
    }

    @Test
    public void invalidPostponedKeysStrategyTest() {
        SecretKeyPassphraseProvider callback = new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                fail("MUST NOT get called in if postponed key strategy is invalid.");
                return null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return true;
            }
        };
        ConsumerOptions options = new ConsumerOptions()
                .setMissingKeyPassphraseStrategy(null) // illegal
                .addDecryptionKey(secretKeys, SecretKeyRingProtector.defaultSecretKeyRingProtector(callback));

        assertThrows(IllegalStateException.class, () -> PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(message))
                .withOptions(options));
    }

    @Test
    public void interactiveStrategy() throws PGPException, IOException {
        // interactive callback
        SecretKeyPassphraseProvider callback = new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                // is called in interactive mode
                return Passphrase.fromPassword(passphrase);
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return true;
            }
        };
        ConsumerOptions options = new ConsumerOptions()
                .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.INTERACTIVE)
                .addDecryptionKey(secretKeys, SecretKeyRingProtector.defaultSecretKeyRingProtector(callback));

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(message))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);

        decryptionStream.close();
        assertArrayEquals("Hey, what's up?".getBytes(StandardCharsets.UTF_8), out.toByteArray());
    }

    @Test
    public void throwExceptionStrategy() throws PGPException, IOException {
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        List<PGPPublicKey> encryptionKeys = info.getEncryptionSubkeys(EncryptionPurpose.ANY);

        SecretKeyPassphraseProvider callback = new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                fail("MUST NOT get called in non-interactive mode.");
                return null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return true;
            }
        };

        ConsumerOptions options = new ConsumerOptions()
                .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.THROW_EXCEPTION)
                .addDecryptionKey(secretKeys, SecretKeyRingProtector.defaultSecretKeyRingProtector(callback));

        try {
            PGPainless.decryptAndOrVerify()
                    .onInputStream(new ByteArrayInputStream(message))
                    .withOptions(options);
            fail("Expected exception!");
        } catch (MissingPassphraseException e) {
            assertFalse(e.getKeyIds().isEmpty());
            assertEquals(encryptionKeys.size(), e.getKeyIds().size());
            for (PGPPublicKey encryptionKey : encryptionKeys) {
                assertTrue(e.getKeyIds().contains(new SubkeyIdentifier(secretKeys, encryptionKey.getKeyID())));
            }
        }
    }
}
