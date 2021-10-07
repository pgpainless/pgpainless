// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import picocli.CommandLine;
import sop.SOP;
import sop.cli.picocli.commands.ArmorCmd;
import sop.cli.picocli.commands.DearmorCmd;
import sop.cli.picocli.commands.DecryptCmd;
import sop.cli.picocli.commands.DetachInbandSignatureAndMessageCmd;
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
                DetachInbandSignatureAndMessageCmd.class,
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
                .setExecutionExceptionHandler(new SOPExecutionExceptionHandler())
                .setExitCodeExceptionMapper(new SOPExceptionExitCodeMapper())
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
