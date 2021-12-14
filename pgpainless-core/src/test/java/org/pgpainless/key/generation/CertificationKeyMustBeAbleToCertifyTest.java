// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.util.ImplementationFactoryTestInvocationContextProvider;

public class CertificationKeyMustBeAbleToCertifyTest {

    /**
     * Generating a key ring that has a primary key which is unable to create signatures (and therefore signatures)
     * would result in an invalid key.
     * This test therefore verifies that generating such keys fails.
     */
    @TestTemplate
    @ExtendWith(ImplementationFactoryTestInvocationContextProvider.class)
    public void testCertificationIncapableKeyTypesThrow() {
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
