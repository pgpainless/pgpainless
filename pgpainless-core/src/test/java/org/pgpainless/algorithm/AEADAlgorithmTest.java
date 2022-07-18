// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AEADAlgorithmTest {

    @Test
    public void testEAXParameters() {
        AEADAlgorithm eax = AEADAlgorithm.EAX;
        assertEquals(1, eax.getAlgorithmId());
        assertEquals(16, eax.getIvLength());
        assertEquals(16, eax.getTagLength());
    }

    @Test
    public void testOCBParameters() {
        AEADAlgorithm ocb = AEADAlgorithm.OCB;
        assertEquals(2, ocb.getAlgorithmId());
        assertEquals(15, ocb.getIvLength());
        assertEquals(16, ocb.getTagLength());
    }

    @Test
    public void testGCMParameters() {
        AEADAlgorithm gcm = AEADAlgorithm.GCM;
        assertEquals(3, gcm.getAlgorithmId());
        assertEquals(12, gcm.getIvLength());
        assertEquals(16, gcm.getTagLength());
    }

    @Test
    public void testFromId() {
        assertEquals(AEADAlgorithm.EAX, AEADAlgorithm.requireFromId(1));
        assertEquals(AEADAlgorithm.OCB, AEADAlgorithm.requireFromId(2));
        assertEquals(AEADAlgorithm.GCM, AEADAlgorithm.requireFromId(3));

        assertNull(AEADAlgorithm.fromId(99));
        assertThrows(NoSuchElementException.class, () -> AEADAlgorithm.requireFromId(99));
    }
}
