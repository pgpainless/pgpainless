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
import static org.pgpainless.sop.Print.print_ln;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import picocli.CommandLine;

@CommandLine.Command(name = "verify",
        description = "Verify a detached signature over the data from standard input",
        exitCodeOnInvalidInput = 37)
public class Verify implements Runnable {

    private static final TimeZone tz = TimeZone.getTimeZone("UTC");
    private static final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");

    private static final Date beginningOfTime = new Date(0);
    private static final Date endOfTime = new Date(8640000000000000L);

    static {
        df.setTimeZone(tz);
    }

    @CommandLine.Parameters(index = "0",
            description = "Detached signature",
            paramLabel = "SIGNATURE")
    File signature;

    @CommandLine.Parameters(index = "1..*",
            arity = "1..*",
            description = "Public key certificates",
            paramLabel = "CERT")
    File[] certificates;

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

    @Override
    public void run() {
        Date notBeforeDate = parseNotBefore();
        Date notAfterDate = parseNotAfter();

        ConsumerOptions options = new ConsumerOptions();
        try (FileInputStream sigIn = new FileInputStream(signature)) {
            options.addVerificationOfDetachedSignatures(sigIn);
        } catch (IOException | PGPException e) {
            err_ln("Cannot read detached signature: " + e.getMessage());
            System.exit(1);
        }

        Map<PGPPublicKeyRing, File> publicKeys = readCertificatesFromFiles();
        if (publicKeys.isEmpty()) {
            err_ln("No certificates supplied.");
            System.exit(19);
        }

        for (PGPPublicKeyRing cert : publicKeys.keySet()) {
            options.addVerificationCert(cert);
        }

        OpenPgpMetadata metadata;
        try {
            DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                    .onInputStream(System.in)
                    .withOptions(options);

            OutputStream out = new NullOutputStream();
            Streams.pipeAll(verifier, out);
            verifier.close();

            metadata = verifier.getResult();
        } catch (IOException | PGPException e) {
            err_ln("Signature validation failed.");
            err_ln(e.getMessage());
            System.exit(1);
            return;
        }

        Map<OpenPgpV4Fingerprint, PGPSignature> signaturesInTimeRange = new HashMap<>();
        for (OpenPgpV4Fingerprint fingerprint : metadata.getVerifiedSignatures().keySet()) {
            PGPSignature signature = metadata.getVerifiedSignatures().get(fingerprint);
            Date creationTime = signature.getCreationTime();
            if (!creationTime.before(notBeforeDate) && !creationTime.after(notAfterDate)) {
                signaturesInTimeRange.put(fingerprint, signature);
            }
        }

        if (signaturesInTimeRange.isEmpty()) {
            err_ln("No valid signatures found.");
            System.exit(3);
        }

        printValidSignatures(signaturesInTimeRange, publicKeys);
    }

    private void printValidSignatures(Map<OpenPgpV4Fingerprint, PGPSignature> validSignatures, Map<PGPPublicKeyRing, File> publicKeys) {
        for (OpenPgpV4Fingerprint sigKeyFp : validSignatures.keySet()) {
            PGPSignature signature = validSignatures.get(sigKeyFp);
            for (PGPPublicKeyRing ring : publicKeys.keySet()) {
                // Search signing key ring
                File file = publicKeys.get(ring);
                if (ring.getPublicKey(sigKeyFp.getKeyId()) == null) {
                    continue;
                }

                String utcSigDate = df.format(signature.getCreationTime());
                OpenPgpV4Fingerprint primaryKeyFp = new OpenPgpV4Fingerprint(ring);
                print_ln(utcSigDate + " " + sigKeyFp.toString() + " " + primaryKeyFp.toString() +
                        " signed by " + file.getName());
            }
        }
    }

    private Map<PGPPublicKeyRing, File> readCertificatesFromFiles() {
        Map<PGPPublicKeyRing, File> publicKeys = new HashMap<>();
        for (File cert : certificates) {
            try (FileInputStream in = new FileInputStream(cert)) {
                PGPPublicKeyRingCollection collection = PGPainless.readKeyRing().publicKeyRingCollection(in);
                for (PGPPublicKeyRing ring : collection) {
                    publicKeys.put(ring, cert);
                }
            } catch (IOException | PGPException e) {
                err_ln("Cannot read certificate from file " + cert.getAbsolutePath() + ":");
                err_ln(e.getMessage());
            }
        }
        return publicKeys;
    }

    private Date parseNotAfter() {
        try {
            return notAfter.equals("now") ? new Date() : notAfter.equals("-") ? endOfTime : df.parse(notAfter);
        } catch (ParseException e) {
            err_ln("Invalid date string supplied as value of --not-after.");
            System.exit(1);
            return null;
        }
    }

    private Date parseNotBefore() {
        try {
            return notBefore.equals("now") ? new Date() : notBefore.equals("-") ? beginningOfTime : df.parse(notBefore);
        } catch (ParseException e) {
            err_ln("Invalid date string supplied as value of --not-before.");
            System.exit(1);
            return null;
        }
    }

    private static class NullOutputStream extends OutputStream {

        @Override
        public void write(int b) throws IOException {
            // Nope
        }
    }
}
