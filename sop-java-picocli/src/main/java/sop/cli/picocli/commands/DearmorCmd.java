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
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;

@CommandLine.Command(name = "dearmor",
        description = "Remove ASCII Armor from standard input",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class DearmorCmd implements Runnable {

    @Override
    public void run() {
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
