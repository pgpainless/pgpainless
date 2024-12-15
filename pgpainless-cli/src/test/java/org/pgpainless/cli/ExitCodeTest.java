// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli;

import org.junit.jupiter.api.Test;
import sop.exception.SOPGPException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExitCodeTest {

    @Test
    public void testUnknownCommand_69() {
        assertEquals(SOPGPException.UnsupportedSubcommand.EXIT_CODE,
                PGPainlessCLI.execute("unsupported-subcommand"));
    }

    @Test
    public void testCommandWithUnknownOption_37() {
        assertEquals(SOPGPException.UnsupportedOption.EXIT_CODE,
                PGPainlessCLI.execute("generate-key", "-k", "\"k is unknown\""));
    }

    @Test
    public void successfulExecutionDoesNotTerminateJVM() {
        assertEquals(0, PGPainlessCLI.execute("version"));
    }
}
