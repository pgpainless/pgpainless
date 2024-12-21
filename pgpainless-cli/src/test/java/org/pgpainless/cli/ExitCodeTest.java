// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli;

import org.junit.jupiter.api.Test;
import org.pgpainless.cli.commands.CLITest;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExitCodeTest extends CLITest {

    public ExitCodeTest() {
        super(LoggerFactory.getLogger(ExitCodeTest.class));
    }

    @Test
    public void testUnknownCommand_69() throws IOException {
        assertEquals(SOPGPException.UnsupportedSubcommand.EXIT_CODE,
                executeCommand("unsupported-subcommand"));
    }

    @Test
    public void testCommandWithUnknownOption_37() throws IOException {
        assertEquals(SOPGPException.UnsupportedOption.EXIT_CODE,
                executeCommand("generate-key", "-k", "\"k is unknown\""));
    }

    @Test
    public void successfulExecutionDoesNotTerminateJVM() throws IOException {
        assertSuccess(executeCommand("version"));
    }
}
