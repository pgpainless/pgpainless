// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.weird_keys;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.WeirdKeys;

public class TestTwoSubkeysEncryption {

    private static final String PLAINTEXT = "Hello World!";

    private ByteArrayInputStream getPlainIn() {
        return new ByteArrayInputStream(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * {@link WeirdKeys#TWO_CRYPT_SUBKEYS} is a key that has two subkeys which both carry the key flags
     * {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS} and {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE}.
     * <p>
     * This test verifies that {@link EncryptionOptions#addRecipient(OpenPGPCertificate, EncryptionOptions.EncryptionKeySelector)}
     * works properly, if {@link EncryptionOptions#encryptToAllCapableSubkeys()} is provided as argument.
     *
     * @throws IOException not expected
     * @throws PGPException not expected
     */
    @Test
    public void testEncryptsToBothSubkeys() throws IOException, PGPException {
        OpenPGPKey twoSuitableSubkeysKeyRing = WeirdKeys.getTwoCryptSubkeysKey();
        OpenPGPCertificate publicKeys = twoSuitableSubkeysKeyRing.toCertificate();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.getInstance().generateMessage()
                .onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(EncryptionOptions.get()
                                .addRecipient(publicKeys, EncryptionOptions.encryptToAllCapableSubkeys())
                        )
                        .setAsciiArmor(false)
                );

        Streams.pipeAll(getPlainIn(), encryptionStream);
        encryptionStream.close();

        EncryptionResult metadata = encryptionStream.getResult();

        assertEquals(2, metadata.getRecipients().size());
    }
}
