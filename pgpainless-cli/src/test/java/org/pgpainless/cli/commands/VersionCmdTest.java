// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

public class VersionCmdTest extends CLITest {

    public VersionCmdTest() {
        super(LoggerFactory.getLogger(VersionCmdTest.class));
    }

    @Test
    public void testVersion() throws IOException {
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("version"));
        assertTrue(out.toString().startsWith("PGPainless-SOP "));
    }

    @Test
    public void testGetBackendVersion() throws IOException {
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("version", "--backend"));
        assertTrue(out.toString().startsWith("PGPainless "));
    }

    @Test
    public void testExtendedVersion() throws IOException {
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("version", "--extended"));
        String info = out.toString();
        assertTrue(info.startsWith("PGPainless-SOP "));
        assertTrue(info.contains("Bouncy Castle"));
        assertTrue(info.contains("Stateless OpenPGP Protocol"));
    }

    @Test
    public void testSopSpecVersion() throws IOException {
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("version", "--sop-spec"));
        String info = out.toString();
        assertTrue(info.startsWith("draft-dkg-openpgp-stateless-cli-"));
    }
}
