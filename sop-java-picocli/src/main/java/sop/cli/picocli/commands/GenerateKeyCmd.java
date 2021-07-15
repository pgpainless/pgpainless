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
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import sop.Ready;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.GenerateKey;

@CommandLine.Command(name = "generate-key",
        description = "Generate a secret key",
        exitCodeOnInvalidInput = 37)
public class GenerateKeyCmd implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Parameters(description = "User-ID, eg. \"Alice <alice@example.com>\"")
    List<String> userId = new ArrayList<>();

    @Override
    public void run() {
        GenerateKey generateKey = SopCLI.getSop().generateKey();
        for (String userId : userId) {
            generateKey.userId(userId);
        }

        if (!armor) {
            generateKey.noArmor();
        }

        try {
            Ready ready = generateKey.generate();
            ready.writeTo(System.out);
        } catch (SOPGPException.MissingArg missingArg) {
            Print.errln("Missing argument.");
            Print.trace(missingArg);
            System.exit(missingArg.getExitCode());
        } catch (SOPGPException.UnsupportedAsymmetricAlgo unsupportedAsymmetricAlgo) {
            Print.errln("Unsupported asymmetric algorithm.");
            Print.trace(unsupportedAsymmetricAlgo);
            System.exit(unsupportedAsymmetricAlgo.getExitCode());
        } catch (IOException e) {
            Print.errln("IO Error.");
            Print.trace(e);
            System.exit(1);
        }
    }
}
