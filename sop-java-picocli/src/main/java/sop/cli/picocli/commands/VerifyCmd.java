/*
 * Copyright 2020 Paul Schaub.
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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import sop.Verification;
import sop.cli.picocli.DateParser;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Verify;

@CommandLine.Command(name = "verify",
        description = "Verify a detached signature over the data from standard input",
        exitCodeOnInvalidInput = 37)
public class VerifyCmd implements Runnable {

    @CommandLine.Parameters(index = "0",
            description = "Detached signature",
            paramLabel = "SIGNATURE")
    File signature;

    @CommandLine.Parameters(index = "1..*",
            arity = "1..*",
            description = "Public key certificates",
            paramLabel = "CERT")
    List<File> certificates = new ArrayList<>();

    @CommandLine.Option(names = {"--not-before"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to beginning of time (\"-\").",
            paramLabel = "DATE")
    String notBefore = "-";

    @CommandLine.Option(names = {"--not-after"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to current system time (\"now\").\n" +
                    "Accepts special value \"-\" for end of time.",
            paramLabel = "DATE")
    String notAfter = "now";

    @Override
    public void run() {
        Verify verify = SopCLI.getSop().verify();
        if (notAfter != null) {
            try {
                verify.notAfter(DateParser.parseNotAfter(notAfter));
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                Print.errln("Unsupported option '--not-after'.");
                Print.trace(unsupportedOption);
                System.exit(unsupportedOption.getExitCode());
            }
        }
        if (notBefore != null) {
            try {
                verify.notBefore(DateParser.parseNotBefore(notBefore));
            } catch (SOPGPException.UnsupportedOption unsupportedOption) {
                Print.errln("Unsupported option '--not-before'.");
                Print.trace(unsupportedOption);
                System.exit(unsupportedOption.getExitCode());
            }
        }

        for (File certFile : certificates) {
            try (FileInputStream certIn = new FileInputStream(certFile)) {
                verify.cert(certIn);
            } catch (FileNotFoundException fileNotFoundException) {
                Print.errln("Certificate file " + certFile.getAbsolutePath() + " not found.");

                Print.trace(fileNotFoundException);
                System.exit(1);
            } catch (IOException ioException) {
                Print.errln("IO Error.");
                Print.trace(ioException);
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                Print.errln("Certificate file " + certFile.getAbsolutePath() + " appears to not contain a valid OpenPGP certificate.");
                Print.trace(badData);
                System.exit(badData.getExitCode());
            }
        }

        if (signature != null) {
            try (FileInputStream sigIn = new FileInputStream(signature)) {
                verify.signatures(sigIn);
            } catch (FileNotFoundException e) {
                Print.errln("Signature file " + signature.getAbsolutePath() + " does not exist.");
                Print.trace(e);
                System.exit(1);
            } catch (IOException e) {
                Print.errln("IO Error.");
                Print.trace(e);
                System.exit(1);
            } catch (SOPGPException.BadData badData) {
                Print.errln("File " + signature.getAbsolutePath() + " does not contain a valid OpenPGP signature.");
                Print.trace(badData);
                System.exit(badData.getExitCode());
            }
        }

        List<Verification> verifications = null;
        try {
            verifications = verify.data(System.in);
        } catch (SOPGPException.NoSignature e) {
            Print.errln("No verifiable signature found.");
            Print.trace(e);
            System.exit(e.getExitCode());
        } catch (IOException ioException) {
            Print.errln("IO Error.");
            Print.trace(ioException);
            System.exit(1);
        } catch (SOPGPException.BadData badData) {
            Print.errln("Standard Input appears not to contain a valid OpenPGP message.");
            Print.trace(badData);
            System.exit(badData.getExitCode());
        }
        for (Verification verification : verifications) {
            Print.outln(verification.toString());
        }
    }
}
