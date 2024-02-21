// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.util.TestAllImplementations;

public class IllegalKeyFlagsTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testKeyCannotCarryFlagsTest() {
        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.XDH(XDHSpec._X25519), KeyFlag.SIGN_DATA));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.XDH(XDHSpec._X25519), KeyFlag.CERTIFY_OTHER));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.XDH(XDHSpec._X25519), KeyFlag.AUTHENTICATION));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.ENCRYPT_COMMS));

        assertThrows(IllegalArgumentException.class, () -> KeySpec.getBuilder(
                KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.ENCRYPT_STORAGE));
    }
}
