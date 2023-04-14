// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sop.SOP;

public class VersionTest {

    private static SOP sop;

    @BeforeAll
    public static void setup() {
        sop = new SOPImpl();
    }

    @Test
    public void testGetVersion() {
        String version = sop.version().getVersion();
        assertNotNull(version);
        assertFalse(version.isEmpty());
    }

    @Test
    public void assertNameEqualsPGPainless() {
        assertEquals("PGPainless-SOP", sop.version().getName());
    }

    @Test
    public void testGetBackendVersion() {
        String backendVersion = sop.version().getBackendVersion();
        assertNotNull(backendVersion);
        assertFalse(backendVersion.isEmpty());
    }

    @Test
    public void testGetExtendedVersion() {
        String extendedVersion = sop.version().getExtendedVersion();
        assertNotNull(extendedVersion);
        assertFalse(extendedVersion.isEmpty());

        String firstLine = extendedVersion.split("\n")[0];
        assertEquals(sop.version().getName() + " " + sop.version().getVersion(), firstLine);
    }

    @Test
    public void testGetSopSpecVersion() {
        boolean incomplete = sop.version().isSopSpecImplementationIncomplete();
        int revisionNumber = sop.version().getSopSpecVersionNumber();

        String revisionString = sop.version().getSopSpecRevisionString();
        assertEquals("draft-dkg-openpgp-stateless-cli-" + String.format("%02d", revisionNumber), revisionString);

        String incompletenessRemarks = sop.version().getSopSpecImplementationIncompletenessRemarks();

        String fullSopSpecVersion = sop.version().getSopSpecVersion();
        if (incomplete) {
            assertTrue(fullSopSpecVersion.startsWith("~" + revisionString));
        } else {
            assertTrue(fullSopSpecVersion.startsWith(revisionString));
        }

        if (incompletenessRemarks != null) {
            assertTrue(fullSopSpecVersion.endsWith(incompletenessRemarks));
        }
    }
}
