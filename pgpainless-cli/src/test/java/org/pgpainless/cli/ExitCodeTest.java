// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import com.ginsberg.junit.exit.FailOnSystemExit;
import org.junit.jupiter.api.Test;
import sop.exception.SOPGPException;

public class ExitCodeTest {

    @Test
    @ExpectSystemExitWithStatus(SOPGPException.UnsupportedSubcommand.EXIT_CODE)
    public void testUnknownCommand_69() {
        PGPainlessCLI.main(new String[] {"generate-kex"});
    }

    @Test
    @ExpectSystemExitWithStatus(SOPGPException.UnsupportedOption.EXIT_CODE)
    public void testCommandWithUnknownOption_37() {
        PGPainlessCLI.main(new String[] {"generate-key", "-k", "\"k is unknown\""});
    }

    @Test
    @FailOnSystemExit
    public void successfulExecutionDoesNotTerminateJVM() {
        PGPainlessCLI.main(new String[] {"version"});
    }
}
