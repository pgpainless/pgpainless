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

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.pgpainless.sop.Print.err_ln;

@CommandLine.Command(name = "armor",
        description = "Add ASCII Armor to standard input")
public class Armor implements Runnable {

    private static final byte[] BEGIN_ARMOR = "-----BEGIN PGP".getBytes(StandardCharsets.UTF_8);

    private enum Label {
        auto,
        sig,
        key,
        cert,
        message
    }

    @CommandLine.Option(names = {"--label"}, description = "Label to be used in the header and tail of the armoring.", paramLabel = "{auto|sig|key|cert|message}")
    Label label;

    @CommandLine.Option(names = {"--allow-nested"}, description = "Allow additional armoring of already armored input")
    boolean allowNested = false;

    @Override
    public void run() {

        try (PushbackInputStream pbIn = new PushbackInputStream(System.in); ArmoredOutputStream armoredOutputStream = ArmoredOutputStreamFactory.get(System.out)) {
            byte[] start = new byte[14];
            int read = pbIn.read(start);
            pbIn.unread(read);
            if (Arrays.equals(BEGIN_ARMOR, start) && !allowNested) {
                Streams.pipeAll(pbIn, System.out);
            } else {
                Streams.pipeAll(pbIn, armoredOutputStream);
            }
        } catch (IOException e) {
            err_ln("Input data cannot be ASCII armored.");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
