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
package sop.cli.picocli;

import picocli.CommandLine;
import sop.SOP;
import sop.cli.picocli.commands.ArmorCmd;
import sop.cli.picocli.commands.DearmorCmd;
import sop.cli.picocli.commands.DecryptCmd;
import sop.cli.picocli.commands.EncryptCmd;
import sop.cli.picocli.commands.ExtractCertCmd;
import sop.cli.picocli.commands.GenerateKeyCmd;
import sop.cli.picocli.commands.SignCmd;
import sop.cli.picocli.commands.VerifyCmd;
import sop.cli.picocli.commands.VersionCmd;

@CommandLine.Command(
        exitCodeOnInvalidInput = 69,
        subcommands = {
                CommandLine.HelpCommand.class,
                ArmorCmd.class,
                DearmorCmd.class,
                DecryptCmd.class,
                EncryptCmd.class,
                ExtractCertCmd.class,
                GenerateKeyCmd.class,
                SignCmd.class,
                VerifyCmd.class,
                VersionCmd.class
        }
)
public class SopCLI {
    // Singleton
    static SOP SOP_INSTANCE;

    public static String EXECUTABLE_NAME = "sop";

    public static void main(String[] args) {
        int exitCode = execute(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    public static int execute(String[] args) {
        return new CommandLine(SopCLI.class)
                .setCommandName(EXECUTABLE_NAME)
                .setCaseInsensitiveEnumValuesAllowed(true)
                .execute(args);
    }

    public static SOP getSop() {
        if (SOP_INSTANCE == null) {
            throw new IllegalStateException("No SOP backend set.");
        }
        return SOP_INSTANCE;
    }

    public static void setSopInstance(SOP instance) {
        SOP_INSTANCE = instance;
    }
}
