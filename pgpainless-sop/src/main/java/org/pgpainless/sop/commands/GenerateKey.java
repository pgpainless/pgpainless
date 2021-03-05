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
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeyRingBuilderInterface;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.sop.Print;
import picocli.CommandLine;

import static org.pgpainless.sop.Print.err_ln;
import static org.pgpainless.sop.Print.print_ln;

@CommandLine.Command(name = "generate-key",
        description = "Generate a secret key",
        exitCodeOnInvalidInput = 37)
public class GenerateKey implements Runnable {

    @CommandLine.Option(names = "--no-armor",
            description = "ASCII armor the output",
            negatable = true)
    boolean armor = true;

    @CommandLine.Parameters(description = "User-ID, eg. \"Alice <alice@example.com>\"")
    List<String> userId;

    @Override
    public void run() {
        if (userId.isEmpty()) {
            print_ln("At least one user-id expected.");
            System.exit(1);
            return;
        }

        try {
            KeyRingBuilderInterface.WithAdditionalUserIdOrPassphrase builder = PGPainless.generateKeyRing()
                    .withSubKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                            .withKeyFlags(KeyFlag.SIGN_DATA)
                            .withDefaultAlgorithms())
                    .withSubKey(KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                            .withKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                            .withDefaultAlgorithms())
                    .withPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                            .withKeyFlags(KeyFlag.CERTIFY_OTHER)
                            .withDefaultAlgorithms())
                    .withPrimaryUserId(userId.get(0));

            for (int i = 1; i < userId.size(); i++) {
                builder.withAdditionalUserId(userId.get(i));
            }

            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            calendar.add(Calendar.YEAR, 3);
            Date expiration = calendar.getTime();

            PGPSecretKeyRing secretKeys = builder.setExpirationDate(expiration)
                    .withoutPassphrase()
                    .build();

            print_ln(Print.toString(secretKeys.getEncoded(), armor));

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | PGPException | IOException e) {
            err_ln("Error creating OpenPGP key:");
            err_ln(e.getMessage());
            System.exit(1);
        }
    }
}
