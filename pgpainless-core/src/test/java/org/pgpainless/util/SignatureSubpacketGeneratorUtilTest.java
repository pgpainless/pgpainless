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
package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Date;

import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.SignatureSubpacket;

public class SignatureSubpacketGeneratorUtilTest {

    @Test
    public void testRemoveAllPacketsOfTypeRemovesAll() {
        PGPSignatureSubpacketGenerator generator = new PGPSignatureSubpacketGenerator();
        generator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        generator.setSignatureCreationTime(false, new Date());
        generator.setSignatureCreationTime(true, new Date());
        PGPSignatureSubpacketVector vector = generator.generate();

        assertEquals(2, vector.getSubpackets(SignatureSubpacketTags.CREATION_TIME).length);
        assertNotNull(vector.getSubpackets(SignatureSubpacketTags.FEATURES));

        generator = new PGPSignatureSubpacketGenerator(vector);
        SignatureSubpacketGeneratorUtil.removeAllPacketsOfType(SignatureSubpacket.signatureCreationTime, generator);
        vector = generator.generate();

        assertEquals(0, vector.getSubpackets(SignatureSubpacketTags.CREATION_TIME).length);
        assertNotNull(vector.getSubpackets(SignatureSubpacketTags.FEATURES));
    }
}
