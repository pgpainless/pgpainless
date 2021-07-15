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

import picocli.CommandLine;
import sop.cli.picocli.Print;
import sop.cli.picocli.SopCLI;
import sop.operation.Version;

@CommandLine.Command(name = "version", description = "Display version information about the tool",
        exitCodeOnInvalidInput = 37)
public class VersionCmd implements Runnable {

    @Override
    public void run() {
        Version version = SopCLI.getSop().version();

        Print.outln(version.getName() + " " + version.getVersion());
    }
}
