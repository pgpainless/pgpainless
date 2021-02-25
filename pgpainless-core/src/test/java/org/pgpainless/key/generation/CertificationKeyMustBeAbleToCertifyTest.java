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

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.xdh.XDHCurve;

public class CertificationKeyMustBeAbleToCertifyTest {

    /**
     * Generating a key ring that has a primary key which is unable to create signatures (and therefore signatures)
     * would result in an invalid key.
     * This test therefore verifies that generating such keys fails.
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void testCertificationIncapableKeyTypesThrow(ImplementationFactory implementationFactory) {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        KeyType[] typesIncapableOfCreatingVerifications = new KeyType[] {
                KeyType.ECDH(EllipticCurve._P256),
                KeyType.ECDH(EllipticCurve._P384),
                KeyType.ECDH(EllipticCurve._P521),
                KeyType.XDH(XDHCurve._X25519)
        };
        for (KeyType type : typesIncapableOfCreatingVerifications) {
            assertThrows(IllegalArgumentException.class, () -> PGPainless
                    .generateKeyRing()
                    .withPrimaryKey(KeySpec
                            .getBuilder(type)
                            .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                            .withDefaultAlgorithms())
                    .withPrimaryUserId("should@throw.ex")
                    .withoutPassphrase().build());
        }
    }
}
