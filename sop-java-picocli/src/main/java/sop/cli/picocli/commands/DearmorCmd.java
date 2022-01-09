// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import java.io.IOException;

import picocli.CommandLine;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Dearmor;

@CommandLine.Command(name = "dearmor",
        description = "Remove ASCII Armor from standard input",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class DearmorCmd implements Runnable {

    @Override
    public void run() {
        Dearmor dearmor = SopCLI.getSop().dearmor();
        if (dearmor == null) {
            throw new SOPGPException.UnsupportedSubcommand("Command 'dearmor' not implemented.");
        }

        try {
            SopCLI.getSop()
                    .dearmor()
                    .data(System.in)
                    .writeTo(System.out);
        } catch (SOPGPException.BadData e) {
            Print.errln("Bad data.");
            Print.trace(e);
            System.exit(e.getExitCode());
        } catch (IOException e) {
            Print.errln("IO Error.");
            Print.trace(e);
            System.exit(1);
        }
    }
}
