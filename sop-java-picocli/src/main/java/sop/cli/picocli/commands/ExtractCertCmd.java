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
