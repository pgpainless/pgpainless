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
package org.pgpainless.sop.commands;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.util.io.Streams;
import picocli.CommandLine;

import java.io.IOException;

import static org.pgpainless.sop.Print.err_ln;

@CommandLine.Command(name = "dearmor",
        description = "Remove ASCII Armor from standard input",
        exitCodeOnInvalidInput = 37)
public class Dearmor implements Runnable {

    @Override
    public void run() {
        try (ArmoredInputStream in = new ArmoredInputStream(System.in, true)) {
            Streams.pipeAll(in, System.out);
        } catch (IOException e) {
            err_ln("Data cannot be dearmored.");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
