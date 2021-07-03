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
package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;

public class GuessPreferredHashAlgorithmTest {

    @Test
    public void guessPreferredHashAlgorithmsAssumesHashAlgoUsedBySelfSig() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .withDetailedConfiguration()
                        // Do not specify preferred algorithms
                        .withPreferredSymmetricAlgorithms(new SymmetricKeyAlgorithm[] {})
                        .withPreferredHashAlgorithms(new HashAlgorithm[] {})
                        .withPreferredCompressionAlgorithms(new CompressionAlgorithm[] {})

                        .done())
                .withPrimaryUserId("test@test.test")
                .withoutPassphrase()
                .build();

        PGPPublicKey publicKey = secretKeys.getPublicKey();
        assertEquals(Collections.emptyList(),
                OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(publicKey));
        assertEquals(Collections.singletonList(HashAlgorithm.SHA512),
                OpenPgpKeyAttributeUtil.guessPreferredHashAlgorithms(publicKey));
    }
}
