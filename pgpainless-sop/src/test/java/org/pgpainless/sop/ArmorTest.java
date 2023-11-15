// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.ArmorUtils;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ArmorTest {

    @Test
    public void labelIsNotSupported() {
        assertThrows(SOPGPException.UnsupportedOption.class, () -> new SOPImpl().armor().label(ArmorLabel.sig));
    }

    @Test
    public void armor() throws IOException {
        byte[] data = PGPainless.generateKeyRing().modernKeyRing("Alice").getEncoded();
        byte[] knownGoodArmor = ArmorUtils.toAsciiArmoredString(data)
                .replace("Version: PGPainless\n", "") // armor command does not add version anymore
                .getBytes(StandardCharsets.UTF_8);
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
