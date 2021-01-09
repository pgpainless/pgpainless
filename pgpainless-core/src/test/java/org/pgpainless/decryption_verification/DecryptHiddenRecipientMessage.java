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
package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DecryptHiddenRecipientMessage {

    private static final String PLAINTEXT = "Hello WOrld";

    /**
     * Message was created using
     * gpg --no-default-keyring --keyring ~/.pgpainless --no-default-recipient --armor --output ~/message.asc --encrypt --hidden-recipient emil@email.user ~/message.txt
     * where ~/.pgpainless was a gnupg keyring containing all the test keys and message.asc contained the plaintext message.
     */
    private static final String CHIPERHTEXT = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "hG4DAAAAAAAAAAASAgMEUif9JYa7qZedAFs0AUUJ3cxdc7tpsREZxhzzFpgWzKbH\n" +
            "YB1i7rp3PM9zO88v3GRQY6TH5tR8CJkHRTWGu03c0SBTUbrzWngh0i2uR9DJnjLk\n" +
            "B8HD4fgn9VP+Qj5Igg6KJdJSAVZlFqVh0H6PCEUaSre/KlyVVqikZKTm0hnWb6XZ\n" +
            "/TrefNuUR6PDNyh/oMbfAQD46UZjfRrbNUdKjOyfwtBYkkcGKTF+HilQbjk1nKud\n" +
            "pojSOQ==\n" +
            "=nyvJ\n" +
            "-----END PGP MESSAGE-----";

    @Test
    public void testDecryptionWithHiddenRecipient() throws IOException, PGPException {
        PGPSecretKeyRingCollection emilSecret = TestKeys.getEmilSecretKeyRingCollection();
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify().onInputStream(new ByteArrayInputStream(CHIPERHTEXT.getBytes(StandardCharsets.UTF_8)))
                .decryptWith(new UnprotectedKeysProtector(), emilSecret)
                .doNotVerify()
                .build();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
    }
}
