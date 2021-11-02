// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;

public class CertificationKeyMustBeAbleToCertifyTest {

    /**
     * Generating a key ring that has a primary key which is unable to create signatures (and therefore signatures)
     * would result in an invalid key.
     * This test therefore verifies that generating such keys fails.
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testCertificationIncapableKeyTypesThrow(ImplementationFactory implementationFactory) {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        KeyType[] typesIncapableOfCreatingVerifications = new KeyType[] {
                KeyType.ECDH(EllipticCurve._P256),
                KeyType.ECDH(EllipticCurve._P384),
                KeyType.ECDH(EllipticCurve._P521),
                KeyType.XDH(XDHSpec._X25519)
        };
        for (KeyType type : typesIncapableOfCreatingVerifications) {
            assertThrows(IllegalArgumentException.class, () -> PGPainless
                    .buildKeyRing()
                    .setPrimaryKey(KeySpec.getBuilder(type, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                    .addUserId("should@throw.ex")
                    .build());
        }
    }
}
