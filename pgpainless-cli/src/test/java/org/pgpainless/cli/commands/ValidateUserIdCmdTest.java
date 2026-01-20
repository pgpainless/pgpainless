// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

public class ValidateUserIdCmdTest extends CLITest {

    public ValidateUserIdCmdTest() {
        super(LoggerFactory.getLogger(ValidateUserIdCmdTest.class));
    }

    @Test
    public void testValidationOfSelfSignature() throws IOException {
        File keyFile = pipeStdoutToFile("a.key");
        assertSuccess(executeCommand("generate-key", "Alice <alice@example.com>"));

        pipeFileToStdin(keyFile);
        File certFile = pipeStdoutToFile("a.cert");
        assertSuccess(executeCommand("extract-cert"));

        assertSuccess(executeCommand("validate-userid", "Alice <alice@example.com>", certFile.getAbsolutePath()));
    }
}
