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
package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.ArmorUtils;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;

public class ArmorTest {

    @Test
    public void labelIsNotSupported() {
        assertThrows(SOPGPException.UnsupportedOption.class, () -> new SOPImpl().armor().label(ArmorLabel.Sig));
    }

    @Test
    public void armor() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        byte[] data = PGPainless.generateKeyRing().modernKeyRing("Alice", null).getEncoded();
        byte[] knownGoodArmor = ArmorUtils.toAsciiArmoredString(data).getBytes(StandardCharsets.UTF_8);
        byte[] armored = new SOPImpl()
                .armor()
                .data(new ByteArrayInputStream(data))
                .getBytes();

        assertArrayEquals(knownGoodArmor, armored);

        byte[] dearmored = new SOPImpl().dearmor()
                .data(new ByteArrayInputStream(knownGoodArmor))
                .getBytes();

        assertArrayEquals(data, dearmored);
    }
}
