/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
        if (signaturesOut == null) {
            throw new SOPGPException.MissingArg("--signatures-out is required.");
        }

        DetachInbandSignatureAndMessage detach = SopCLI.getSop().detachInbandSignatureAndMessage();
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
