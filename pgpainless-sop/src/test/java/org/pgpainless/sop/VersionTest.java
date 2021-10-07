// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class VersionTest {

    @Test
    public void testGetVersion() {
        assertNotNull(new SOPImpl().version().getVersion());
    }

    @Test
    public void assertNameEqualsPGPainless() {
        assertEquals("PGPainless-SOP", new SOPImpl().version().getName());
    }
}
