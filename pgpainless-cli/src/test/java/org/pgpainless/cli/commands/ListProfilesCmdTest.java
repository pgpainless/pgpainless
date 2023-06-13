// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

public class ListProfilesCmdTest extends CLITest {

    public ListProfilesCmdTest() {
        super(LoggerFactory.getLogger(ListProfilesCmdTest.class));
    }

    @Test
    public void listProfilesWithoutCommand() throws IOException {
        assertNotEquals(0, executeCommand("list-profiles"));
    }

    @Test
    public void listProfileOfGenerateKey() throws IOException {
        ByteArrayOutputStream output = pipeStdoutToStream();
        assertSuccess(executeCommand("list-profiles", "generate-key"));

        assertTrue(output.toString().contains("rfc4880"));
    }

    @Test
    public void listProfilesOfEncrypt() throws IOException {
        ByteArrayOutputStream output = pipeStdoutToStream();
        assertSuccess(executeCommand("list-profiles", "encrypt"));

        assertTrue(output.toString().contains("rfc4880"));
    }
}
