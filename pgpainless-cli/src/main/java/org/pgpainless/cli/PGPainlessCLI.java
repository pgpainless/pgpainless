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
        SopCLI.setSopInstance(new SOPImpl());
    }

    public static void main(String[] args) {
        int result = execute(args);
        if (result != 0) {
            System.exit(result);
        }
    }

    public static int execute(String... args) {
        return SopCLI.execute(args);
    }
}
