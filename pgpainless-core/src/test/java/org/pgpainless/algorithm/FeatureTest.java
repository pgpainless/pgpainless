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
