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
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.WeirdKeys;
import org.pgpainless.key.util.KeyRingUtils;

public class TestTwoSubkeysEncryption {

    private static final String PLAINTEXT = "Hello World!";

    private ByteArrayInputStream getPlainIn() {
        return new ByteArrayInputStream(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * {@link WeirdKeys#TWO_CRYPT_SUBKEYS} is a key that has two subkeys which both carry the key flags
     * {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS} and {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE}.
     *
     * This test verifies that {@link EncryptionOptions#addRecipient(PGPPublicKeyRing, EncryptionOptions.EncryptionKeySelector)}
     * works properly, if {@link EncryptionOptions#encryptToAllCapableSubkeys()} is provided as argument.
     *
     * @throws IOException not expected
     * @throws PGPException not expected
     */
    @Test
    public void testEncryptsToBothSubkeys() throws IOException, PGPException {
        PGPSecretKeyRing twoSuitableSubkeysKeyRing = WeirdKeys.getTwoCryptSubkeysKey();
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(twoSuitableSubkeysKeyRing);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(new EncryptionOptions(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS)
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
