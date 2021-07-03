/*
 * Copyright 2020 Paul Schaub.
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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.ArmorUtils;

public class GenerateEllipticCurveKeyTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void test(ImplementationFactory implementationFactory) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing keyRing = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .withDefaultAlgorithms())
                .withPrimaryUserId(UserId.onlyEmail("alice@wonderland.lit").toString())
                .withoutPassphrase()
                .build();
        // CHECKSTYLE:OFF
        System.out.println(ArmorUtils.toAsciiArmoredString(keyRing));
        // CHECKSTYLE:ON
    }
}
