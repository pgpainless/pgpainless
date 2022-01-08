// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import sop.MicAlg;
import sop.ReadyWithResult;
import sop.SigningResult;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.enums.SignAs;
import sop.exception.SOPGPException;
import sop.operation.Sign;

@CommandLine.Command(name = "sign",
        description = "Create a detached signature on the data from standard input",
        exitCodeOnInvalidInput = 37)
public class SignCmd implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Option(names = "--as", description = "Defaults to 'binary'. If '--as=text' and the input data is not valid UTF-8, sign fails with return code 53.",
            paramLabel = "{binary|text}")
    SignAs type;

    @CommandLine.Parameters(description = "Secret keys used for signing",
            paramLabel = "KEYS")
    List<File> secretKeyFile = new ArrayList<>();

    @CommandLine.Option(names = "--micalg-out", description = "Emits the digest algorithm used to the specified file in a way that can be used to populate the micalg parameter for the PGP/MIME Content-Type (RFC3156)",
            paramLabel = "MICALG")
    File micAlgOut;

    @Override
    public void run() {
        Sign sign = SopCLI.getSop().sign();

        if (type != null) {
            try {
                sign.mode(type);
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                Print.errln("Unsupported option '--as'");
                Print.trace(unsupportedOption);
                System.exit(unsupportedOption.getExitCode());
            }
        }

        if (micAlgOut != null && micAlgOut.exists()) {
            throw new SOPGPException.OutputExists(String.format("Target %s of option %s already exists.", micAlgOut.getAbsolutePath(), "--micalg-out"));
        }

        if (secretKeyFile.isEmpty()) {
            Print.errln("Missing required parameter 'KEYS'.");
            System.exit(19);
        }

        for (File keyFile : secretKeyFile) {
            try (FileInputStream keyIn = new FileInputStream(keyFile)) {
                sign.key(keyIn);
            } catch (FileNotFoundException e) {
                Print.errln("File " + keyFile.getAbsolutePath() + " does not exist.");
                Print.trace(e);
                System.exit(1);
            } catch (IOException e) {
                Print.errln("Cannot access file " + keyFile.getAbsolutePath());
                Print.trace(e);
                System.exit(1);
            } catch (SOPGPException.KeyIsProtected e) {
                Print.errln("Key " + keyFile.getName() + " is password protected.");
                Print.trace(e);
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                Print.errln("Bad data in key file " + keyFile.getAbsolutePath() + ":");
                Print.trace(badData);
                System.exit(badData.getExitCode());
            }
        }

        if (!armor) {
            sign.noArmor();
        }

        try {
            ReadyWithResult<SigningResult> ready = sign.data(System.in);
            SigningResult result = ready.writeTo(System.out);

            MicAlg micAlg = result.getMicAlg();
            if (micAlgOut != null) {
                // Write micalg out
                micAlgOut.createNewFile();
                FileOutputStream micAlgOutStream = new FileOutputStream(micAlgOut);
                micAlg.writeTo(micAlgOutStream);
                micAlgOutStream.close();
            }
        } catch (IOException e) {
            Print.errln("IO Error.");
            Print.trace(e);
            System.exit(1);
        } catch (SOPGPException.ExpectedText expectedText) {
            Print.errln("Expected text input, but got binary data.");
            Print.trace(expectedText);
            System.exit(expectedText.getExitCode());
        }
    }
}
