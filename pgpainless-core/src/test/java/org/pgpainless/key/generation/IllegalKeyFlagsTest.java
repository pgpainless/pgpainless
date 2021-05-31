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
package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;

public class IllegalKeyFlagsTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void testKeyCannotCarryFlagsTest(ImplementationFactory implementationFactory) {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        assertThrows(IllegalArgumentException.class, () -> PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519))
                        .withKeyFlags(KeyFlag.SIGN_DATA) // <- should throw
                        .withDefaultAlgorithms()));

        assertThrows(IllegalArgumentException.class, () -> PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER) // <- should throw
                        .withDefaultAlgorithms()));

        assertThrows(IllegalArgumentException.class, () -> PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519))
                        .withKeyFlags(KeyFlag.AUTHENTICATION) // <- should throw
                        .withDefaultAlgorithms()));

        assertThrows(IllegalArgumentException.class, () -> PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS) // <- should throw
                        .withDefaultAlgorithms()));

        assertThrows(IllegalArgumentException.class, () -> PGPainless.generateKeyRing()
                .withPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_STORAGE) // <- should throw as well
                        .withDefaultAlgorithms()));
    }
}
