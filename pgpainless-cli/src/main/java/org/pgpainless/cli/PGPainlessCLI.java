// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli;

import org.pgpainless.sop.SOPImpl;
import sop.cli.picocli.SopCLI;

/**
 * This class merely binds PGPainless to {@link SopCLI} by injecting a {@link SOPImpl} instance.
 * CLI command calls are then simply forwarded to {@link SopCLI#execute(String[])}.
 */
public class PGPainlessCLI {

    static {
        // Prevent slf4j initialization logging
        // https://github.com/qos-ch/slf4j/issues/422#issuecomment-2277280185
        System.setProperty("slf4j.internal.verbosity", "WARN");

        SopCLI.EXECUTABLE_NAME = "pgpainless-cli";
        SopCLI.setSopInstance(new SOPImpl());
    }

    /**
     * Main method of the CLI application.
     * @param args arguments
     */
    public static void main(String[] args) {
        int result = execute(args);
        if (result != 0) {
            System.exit(result);
        }
    }

    /**
     * Execute the given command and return the exit code of the program.
     *
     * @param args command string array (e.g. ["pgpainless-cli", "generate-key", "Alice"])
     * @return exit code
     */
    public static int execute(String... args) {
        return SopCLI.execute(args);
    }
}
