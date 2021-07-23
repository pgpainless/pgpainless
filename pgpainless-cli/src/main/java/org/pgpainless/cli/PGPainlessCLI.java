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
package org.pgpainless.cli;

import org.pgpainless.sop.SOPImpl;
import sop.cli.picocli.SopCLI;

public class PGPainlessCLI {

    static {
        SopCLI.EXECUTABLE_NAME = "pgpainless-cli";
        SopCLI.setSopInstance(new SOPImpl());
    }

    public static void main(String[] args) {
        int result = execute(args);
        if (result != 0) {
            System.exit(result);
        }
    }

    public static int execute(String... args) {
        return SopCLI.execute(args);
    }
}
