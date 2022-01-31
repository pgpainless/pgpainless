// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import pgp.cert_d.cli.PGPCertDCli;
import picocli.CommandLine;

@CommandLine.Command(
        name = "print-directory",
        description = "Print the location of the certificate directory"
)
public class PrintDirectory implements Runnable {

    @Override
    public void run() {
        // CHECKSTYLE:OFF
        System.out.println(PGPCertDCli.getBaseDir());
        // CHECKSTYLE:ON
    }
}
