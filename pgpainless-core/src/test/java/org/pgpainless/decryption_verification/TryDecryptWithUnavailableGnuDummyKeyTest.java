// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
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
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("Hardy Hardware <hardy@hard.ware>");
        OpenPGPCertificate certificate = secretKeys.toCertificate();

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(ciphertextOut)
                .withOptions(
                        ProducerOptions.encrypt(EncryptionOptions.get(api).addRecipient(certificate)));
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream("Hello, World!\n".getBytes());
        Streams.pipeAll(plaintextIn, encryptionStream);
        encryptionStream.close();

        OpenPGPKey removedKeys = api.toKey(
                GnuPGDummyKeyUtil.modify(secretKeys)
                    .removePrivateKeys(GnuPGDummyKeyUtil.KeyFilter.any()));

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertextOut.toByteArray());
        assertThrows(MissingDecryptionMethodException.class, () -> api.processMessage()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get(api).addDecryptionKey(removedKeys)));
    }
}
