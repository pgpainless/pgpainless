// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.ascii_armor.ArmorUtils;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;

public class ArmorTest {

    @Test
    public void labelIsNotSupported() {
        assertThrows(SOPGPException.UnsupportedOption.class, () -> new SOPImpl().armor().label(ArmorLabel.Sig));
    }

    @Test
    public void armor() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        byte[] data = PGPainless.generateKeyRing().modernKeyRing("Alice").getEncoded();
        byte[] knownGoodArmor = ArmorUtils.toAsciiArmoredString(data).getBytes(StandardCharsets.UTF_8);
        byte[] armored = new SOPImpl()
                .armor()
                .data(data)
                .getBytes();

        assertArrayEquals(knownGoodArmor, armored);

        byte[] dearmored = new SOPImpl().dearmor()
                .data(knownGoodArmor)
                .getBytes();

        assertArrayEquals(data, dearmored);
    }
}
