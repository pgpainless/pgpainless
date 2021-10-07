// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import picocli.CommandLine;
import sop.exception.SOPGPException;

public class SOPExceptionExitCodeMapper implements CommandLine.IExitCodeExceptionMapper {

    @Override
    public int getExitCode(Throwable exception) {
        if (exception instanceof SOPGPException) {
            return ((SOPGPException) exception).getExitCode();
        }
        if (exception instanceof CommandLine.UnmatchedArgumentException) {
            CommandLine.UnmatchedArgumentException ex = (CommandLine.UnmatchedArgumentException) exception;
            // Unmatched option of subcommand (eg. `generate-key -k`)
            if (ex.isUnknownOption()) {
                return SOPGPException.UnsupportedOption.EXIT_CODE;
            }
            // Unmatched subcommand
            return SOPGPException.UnsupportedSubcommand.EXIT_CODE;
        }
        // Invalid option (eg. `--label Invalid`)
        if (exception instanceof CommandLine.ParameterException) {
            return SOPGPException.UnsupportedOption.EXIT_CODE;
        }

        // Others, like IOException etc.
        return 1;
    }
}
