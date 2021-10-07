// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
import org.pgpainless.signature.subpackets.SignatureSubpacketGeneratorUtil;

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
