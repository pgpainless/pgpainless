// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import java.io.IOException;

import picocli.CommandLine;
import sop.Ready;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

@CommandLine.Command(name = "armor",
        description = "Add ASCII Armor to standard input",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class ArmorCmd implements Runnable {

    @CommandLine.Option(names = {"--label"}, description = "Label to be used in the header and tail of the armoring.", paramLabel = "{auto|sig|key|cert|message}")
    ArmorLabel label;

    @Override
    public void run() {
        Armor armor = SopCLI.getSop().armor();
        if (armor == null) {
            throw new SOPGPException.UnsupportedSubcommand("Command 'armor' not implemented.");
        }

        if (label != null) {
            try {
                armor.label(label);
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                Print.errln("Armor labels not supported.");
                System.exit(unsupportedOption.getExitCode());
            }
        }

        try {
            Ready ready = armor.data(System.in);
            ready.writeTo(System.out);
        } catch (SOPGPException.BadData badData) {
            Print.errln("Bad data.");
            Print.trace(badData);
            System.exit(badData.getExitCode());
        } catch (IOException e) {
            Print.errln("IO Error.");
            Print.trace(e);
            System.exit(1);
        }
    }
}
