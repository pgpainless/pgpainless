/*
 * Copyright 2020 Wiktor Kwapisiewicz, 2020 Paul Schaub.
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
package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.util.Passphrase;

/**
 * Reproduce behavior of https://github.com/pgpainless/pgpainless/issues/16
 * and verify that the fix is working.
 *
 * The issue is that the implementation of {@link Passphrase#emptyPassphrase()} would set the underlying
 * char array to null, which caused an NPE later on.
 */
public class GenerateWithEmptyPassphrase {

    @Test
    public void testGeneratingKeyWithEmptyPassphraseDoesNotThrow() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        assertNotNull(PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withPrimaryUserId("primary@user.id")
                .withPassphrase(Passphrase.emptyPassphrase())
                .build());
    }
}
