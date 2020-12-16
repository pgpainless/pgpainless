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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.sop.Print;
import org.pgpainless.util.BCUtil;
import picocli.CommandLine;

import static org.pgpainless.sop.Print.err_ln;
import static org.pgpainless.sop.Print.print_ln;

@CommandLine.Command(name = "extract-cert")
public class ExtractCert implements Runnable {

    @CommandLine.Option(names = {"--armor"}, description = "ASCII Armor the output")
    boolean armor = false;

    @CommandLine.Option(names = {"--no-armor"})
    boolean noArmor = false;

    @Override
    public void run() {
        try {
            PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(System.in);
            PGPPublicKeyRing publicKeys = BCUtil.publicKeyRingFromSecretKeyRing(secretKeys);

            print_ln(Print.toString(publicKeys.getEncoded(), !noArmor));
        } catch (IOException | PGPException e) {
            err_ln("Error extracting certificate from keys;");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
