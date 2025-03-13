// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class InvalidProtectionSettingsTest {

    @Test
    public void unencryptedKeyRingProtectionSettingsThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                new KeyRingProtectionSettings(SymmetricKeyAlgorithm.NULL, HashAlgorithm.SHA256, 0x60, false));
    }
}
