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

import static org.pgpainless.sop.Print.err_ln;
import static org.pgpainless.sop.SopKeyUtil.loadKeysFromFiles;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.DecryptionBuilderInterface;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import picocli.CommandLine;

@CommandLine.Command(name = "decrypt",
        description = "Decrypt a message from standard input")
public class Decrypt implements Runnable {

    private static final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");

    @CommandLine.Option(
            names = {"--session-key-out"},
            description = "Can be used to learn the session key on successful decryption",
            paramLabel = "SESSIONKEY")
    File sessionKeyOut;

    @CommandLine.Option(
            names = {"--with-session-key"},
            description = "Enables decryption of the \"CIPHERTEXT\" using the session key directly against the \"SEIPD\" packet",
            paramLabel = "SESSIONKEY")
    File[] withSessionKey;

    @CommandLine.Option(
            names = {"--with-password"},
            description = "Enables decryption based on any \"SKESK\" packets in the \"CIPHERTEXT\"",
            paramLabel = "PASSWORD")
    String[] withPassword;

    @CommandLine.Option(names = {"--verify-out"},
            description = "Produces signature verification status to the designated file",
            paramLabel = "VERIFICATIONS")
    File verifyOut;

    @CommandLine.Option(names = {"--verify-with"},
            description = "Certificates whose signatures would be acceptable for signatures over this message",
            paramLabel = "CERT")
    File[] certs;

    @CommandLine.Option(names = {"--not-before"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to beginning of time (\"-\").",
            paramLabel = "DATE")
    String notBefore = "-";

    @CommandLine.Option(names = {"--not-after"},
            description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
                    "Reject signatures with a creation date not in range.\n" +
                    "Defaults to current system time (\"now\").\n" +
                    "Accepts special value \"-\" for end of time.",
            paramLabel = "DATE")
    String notAfter = "now";

    @CommandLine.Parameters(index = "0..*",
            description = "Secret keys to attempt decryption with",
            paramLabel = "KEY")
    File[] keys;

    @Override
    public void run() {
        if (verifyOut == null ^ certs == null) {
            err_ln("To enable signature verification, both --verify-out and at least one --verify-with argument must be supplied.");
            System.exit(23);
        }

        if (sessionKeyOut != null || withSessionKey != null) {
            err_ln("session key in and out are not yet supported.");
            System.exit(1);
        }

        PGPSecretKeyRingCollection secretKeys;
        try {
            List<PGPSecretKeyRing> secretKeyRings = loadKeysFromFiles(keys);
            secretKeys = new PGPSecretKeyRingCollection(secretKeyRings);
        } catch (PGPException | IOException e) {
            err_ln(e.getMessage());
            System.exit(1);
            return;
        }

        List<PGPPublicKeyRing> verifyWith = new ArrayList<>();
        if (certs != null) {
            for (File f : certs) {
                try {
                    verifyWith.add(PGPainless.readKeyRing().publicKeyRing(new FileInputStream(f)));
                } catch (IOException e) {

                }
            }
        }


        DecryptionBuilderInterface.Verify builder = PGPainless.decryptAndOrVerify()
                .onInputStream(System.in)
                .decryptWith(secretKeys);
        DecryptionStream decryptionStream = null;
        try {
            if (certs != null) {
                decryptionStream = builder.verifyWith(new HashSet<>(verifyWith))
                        .ignoreMissingPublicKeys().build();
            } else {
                decryptionStream = builder.doNotVerify()
                        .build();
            }
        } catch (IOException | PGPException e) {
            System.exit(1);
            return;
        }

        try {
            Streams.pipeAll(decryptionStream, System.out);
            decryptionStream.close();
        } catch (IOException e) {
            err_ln("Unable to decrypt: " + e.getMessage());
            System.exit(29);
        }
        if (verifyOut == null) {
            return;
        }

        OpenPgpMetadata metadata = decryptionStream.getResult();
        StringBuilder sb = new StringBuilder();
        for (OpenPgpV4Fingerprint fingerprint : metadata.getVerifiedSignatures().keySet()) {
            PGPPublicKeyRing verifier = null;
            for (PGPPublicKeyRing ring : verifyWith) {
                if (ring.getPublicKey(fingerprint.getKeyId()) != null) {
                    verifier = ring;
                    break;
                }
            }
            PGPSignature signature = metadata.getVerifiedSignatures().get(fingerprint);
            sb.append(df.format(signature.getCreationTime())).append(' ')
                    .append(fingerprint).append(' ')
                    .append(new OpenPgpV4Fingerprint(verifier)).append('\n');
        }

        try {
            verifyOut.createNewFile();
            PrintStream verifyPrinter = new PrintStream(new FileOutputStream(verifyOut));
            // CHECKSTYLE:OFF
            verifyPrinter.println(sb.toString());
            // CHECKSTYLE:ON
            verifyPrinter.close();
        } catch (IOException e) {
        }
    }
}
