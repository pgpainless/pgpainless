// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.gnupg.GnuPGDummyKeyUtil;
import org.pgpainless.exception.MissingDecryptionMethodException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class TryDecryptWithUnavailableGnuDummyKeyTest {

    @Test
    public void testAttemptToDecryptWithRemovedPrivateKeysThrows()
            throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Hardy Hardware <hardy@hard.ware>")
                .getPGPSecretKeyRing();
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertextOut)
                .withOptions(
                        ProducerOptions.encrypt(EncryptionOptions.get().addRecipient(certificate)));
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream("Hello, World!\n".getBytes());
        Streams.pipeAll(plaintextIn, encryptionStream);
        encryptionStream.close();

        PGPSecretKeyRing removedKeys = GnuPGDummyKeyUtil.modify(secretKeys)
                .removePrivateKeys(GnuPGDummyKeyUtil.KeyFilter.any());

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertextOut.toByteArray());
        assertThrows(MissingDecryptionMethodException.class, () -> PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get().addDecryptionKey(removedKeys)));
    }
}
