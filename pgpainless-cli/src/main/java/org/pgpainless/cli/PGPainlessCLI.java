// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli;

import org.pgpainless.sop.SOPImpl;
import sop.cli.picocli.SopCLI;

public class PGPainlessCLI {

    static {
        SopCLI.EXECUTABLE_NAME = "pgpainless-cli";
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
