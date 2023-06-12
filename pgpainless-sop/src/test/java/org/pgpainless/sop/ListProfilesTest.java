// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sop.SOP;
import sop.exception.SOPGPException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ListProfilesTest {

    private SOP sop;

    @BeforeEach
    public void prepare() {
        this.sop = new SOPImpl();
    }

    @Test
    public void listProfilesOfGenerateKey() {
        assertFalse(sop.listProfiles().subcommand("generate-key").isEmpty());
    }

    @Test
    public void listProfilesOfHelpCommandThrows() {
        assertThrows(SOPGPException.UnsupportedProfile.class, () ->
                sop.listProfiles().subcommand("help"));
    }

    @Test
    public void listProfilesOfNullThrows() {
        assertThrows(SOPGPException.UnsupportedProfile.class, () ->
                sop.listProfiles().subcommand(null));
    }
}
