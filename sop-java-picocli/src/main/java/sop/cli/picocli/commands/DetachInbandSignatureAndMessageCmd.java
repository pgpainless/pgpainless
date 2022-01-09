// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import picocli.CommandLine;
import sop.Signatures;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.DetachInbandSignatureAndMessage;

@CommandLine.Command(name = "detach-inband-signature-and-message",
        description = "Split a clearsigned message",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class DetachInbandSignatureAndMessageCmd implements Runnable {

    @CommandLine.Option(
            names = {"--signatures-out"},
            description = "Destination to which a detached signatures block will be written",
            paramLabel = "SIGNATURES")
    File signaturesOut;

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @Override
    public void run() {
        DetachInbandSignatureAndMessage detach = SopCLI.getSop().detachInbandSignatureAndMessage();
        if (detach == null) {
            throw new SOPGPException.UnsupportedSubcommand("Command 'detach-inband-signature-and-message' not implemented.");
        }

        if (signaturesOut == null) {
            throw new SOPGPException.MissingArg("--signatures-out is required.");
        }

        if (!armor) {
            detach.noArmor();
        }

        try {
            Signatures signatures = detach
                    .message(System.in).writeTo(System.out);
            if (!signaturesOut.createNewFile()) {
                throw new SOPGPException.OutputExists("Destination of --signatures-out already exists.");
            }
            signatures.writeTo(new FileOutputStream(signaturesOut));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
