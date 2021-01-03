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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.sop.Print;
import picocli.CommandLine;

import static org.pgpainless.sop.Print.err_ln;
import static org.pgpainless.sop.Print.print_ln;

@CommandLine.Command(name = "generate-key", description = "Generate a secret key")
public class GenerateKey implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Parameters(description = "User-ID, eg. \"Alice <alice@example.com>\"")
    String userId;

    @Override
    public void run() {
        try {
            PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing(userId);

            print_ln(Print.toString(secretKeys.getEncoded(), armor));

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | PGPException | IOException e) {
            err_ln("Error creating OpenPGP key:");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
