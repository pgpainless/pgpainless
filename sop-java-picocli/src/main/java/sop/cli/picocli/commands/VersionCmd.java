// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import picocli.CommandLine;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Version;

@CommandLine.Command(name = "version", description = "Display version information about the tool",
        exitCodeOnInvalidInput = 37)
public class VersionCmd implements Runnable {

    @CommandLine.ArgGroup()
    Exclusive exclusive;

    static class Exclusive {
        @CommandLine.Option(names = "--extended", description = "Print an extended version string.")
        boolean extended;

        @CommandLine.Option(names = "--backend", description = "Print information about the cryptographic backend.")
        boolean backend;
    }



    @Override
    public void run() {
        Version version = SopCLI.getSop().version();
        if (version == null) {
            throw new SOPGPException.UnsupportedSubcommand("Command 'version' not implemented.");
        }

        if (exclusive == null) {
            Print.outln(version.getName() + " " + version.getVersion());
            return;
        }

        if (exclusive.extended) {
            Print.outln(version.getExtendedVersion());
            return;
        }

        if (exclusive.backend) {
            Print.outln(version.getBackendVersion());
            return;
        }
    }
}
