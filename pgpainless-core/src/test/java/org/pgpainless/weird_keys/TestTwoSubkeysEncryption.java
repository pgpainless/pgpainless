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
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign(EncryptionStream.Purpose.STORAGE)
                .onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(new EncryptionOptions(EncryptionStream.Purpose.STORAGE_AND_COMMUNICATIONS)
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
