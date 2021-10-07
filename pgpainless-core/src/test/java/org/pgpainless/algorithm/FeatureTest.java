// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class FeatureTest {

    @Test
    public void testModificationDetection() {
        Feature modificationDetection = Feature.MODIFICATION_DETECTION;
        assertEquals(0x01, modificationDetection.getFeatureId());
        assertEquals(modificationDetection, Feature.fromId((byte) 0x01));
    }

    @Test
    public void testFromInvalidIdIsNull() {
        assertNull(Feature.fromId((byte) 0x99));
    }
}
