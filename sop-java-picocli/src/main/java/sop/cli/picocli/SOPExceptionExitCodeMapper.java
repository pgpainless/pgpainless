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
