// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import java.io.IOException;

import picocli.CommandLine;
import sop.Ready;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.ExtractCert;

@CommandLine.Command(name = "extract-cert",
        description = "Extract a public key certificate from a secret key from standard input",
        exitCodeOnInvalidInput = 37)
public class ExtractCertCmd implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @Override
    public void run() {
        ExtractCert extractCert = SopCLI.getSop().extractCert();
        if (!armor) {
            extractCert.noArmor();
        }

        try {
            Ready ready = extractCert.key(System.in);
            ready.writeTo(System.out);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (SOPGPException.BadData badData) {
            throw new SOPGPException.BadData("Standard Input does not contain valid OpenPGP private key material.", badData);
        }
    }
}
