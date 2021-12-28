// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import picocli.CommandLine;

public class SOPExecutionExceptionHandler implements CommandLine.IExecutionExceptionHandler {

    @Override
    public int handleExecutionException(Exception ex, CommandLine commandLine, CommandLine.ParseResult parseResult) {
        int exitCode = commandLine.getExitCodeExceptionMapper() != null ?
                commandLine.getExitCodeExceptionMapper().getExitCode(ex) :
                commandLine.getCommandSpec().exitCodeOnExecutionException();
        CommandLine.Help.ColorScheme colorScheme = commandLine.getColorScheme();
        // CHECKSTYLE:OFF
        if (ex.getMessage() != null) {
            commandLine.getErr().println(colorScheme.errorText(ex.getMessage()));
        }
        ex.printStackTrace(commandLine.getErr());
        // CHECKSTYLE:ON

        return exitCode;
    }
}
