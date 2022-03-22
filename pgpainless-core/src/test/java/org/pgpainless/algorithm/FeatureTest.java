// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class FeatureTest {

    @Test
    public void testAll() {
        for (Feature feature : Feature.values()) {
            assertEquals(feature, Feature.fromId(feature.getFeatureId()));
            assertEquals(feature, Feature.requireFromId(feature.getFeatureId()));
        }
    }

    @Test
    public void testModificationDetection() {
        Feature modificationDetection = Feature.MODIFICATION_DETECTION;
        assertEquals(0x01, modificationDetection.getFeatureId());
        assertEquals(modificationDetection, Feature.fromId((byte) 0x01));
        assertEquals(modificationDetection, Feature.requireFromId((byte) 0x01));
    }

    @Test
    public void testFromInvalidIdIsNull() {
        assertNull(Feature.fromId((byte) 0x99));
    }

    @Test
    public void testRequireFromInvalidThrows() {
        assertThrows(NoSuchElementException.class, () -> Feature.requireFromId((byte) 0x99));
    }
}
