// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;

public class IllegalKeyFlagsTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testKeyCannotCarryFlagsTest(ImplementationFactory implementationFactory) {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.XDH(XDHSpec._X25519), KeyFlag.SIGN_DATA));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.XDH(XDHSpec._X25519), KeyFlag.CERTIFY_OTHER));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.XDH(XDHSpec._X25519), KeyFlag.AUTHENTICATION));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.ENCRYPT_COMMS));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.ENCRYPT_STORAGE));
    }
}
