package org.pgpainless.sop.commands;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import picocli.CommandLine;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.TimeZone;

@CommandLine.Command(name = "verify", description = "Verify a detached signature.\nThe signed data is being read from standard input.")
public class Verify implements Runnable {

    @CommandLine.Parameters(index = "0", description = "Detached signature")
    File signature;

    @CommandLine.Parameters(index = "1..*", arity = "1..*", description = "Public key certificates")
    File[] certificates;

    @CommandLine.Option(names = {"--not-before"}, description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
            "Reject signatures with a creation date not in range.\n" +
            "Defaults to beginning of time (\"-\").")
            String notBefore = "-";

    @CommandLine.Option(names = {"--not-after"}, description = "ISO-8601 formatted UTC date (eg. '2020-11-23T16:35Z)\n" +
            "Reject signatures with a creation date not in range.\n" +
            "Defaults to current system time (\"now\").\n" +
            "Accepts special value \"-\" for end of time.")
            String notAfter = "now";

    private final TimeZone tz = TimeZone.getTimeZone("UTC");
    private final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");

    private final Date beginningOfTime = new Date(0);
    private final Date endOfTime = new Date(8640000000000000L);

    @Override
    public void run() {
        df.setTimeZone(tz);
        Date notBeforeDate = parseNotBefore();
        Date notAfterDate = parseNotAfter();

        Map<File, PGPPublicKeyRing> publicKeys = readCertificatesFromFiles();
        if (publicKeys.isEmpty()) {
            System.out.println("No certificates supplied.");
            System.exit(19);
        }

        try(FileInputStream sigIn = new FileInputStream(signature)) {
            DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                    .onInputStream(System.in)
                    .doNotDecrypt()
                    .verifyDetachedSignature(sigIn)
                    .verifyWith(new HashSet<>(publicKeys.values()))
                    .ignoreMissingPublicKeys()
                    .build();

            OutputStream out = new NullOutputStream();
            Streams.pipeAll(verifier, out);
            verifier.close();

            OpenPgpMetadata metadata = verifier.getResult();

            Map<OpenPgpV4Fingerprint, PGPSignature> signaturesInTimeRange = new HashMap<>();
            for (OpenPgpV4Fingerprint fingerprint : metadata.getVerifiedSignatures().keySet()) {
                PGPSignature signature = metadata.getVerifiedSignatures().get(fingerprint);
                Date creationTime = signature.getCreationTime();
                if (!creationTime.before(notBeforeDate) && !creationTime.after(notAfterDate)) {
                    signaturesInTimeRange.put(fingerprint, signature);
                }
            }

            if (signaturesInTimeRange.isEmpty()) {
                System.out.println("Signature validation failed.");
                System.exit(3);
            }

            printValidSignatures(signaturesInTimeRange, publicKeys);
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    private void printValidSignatures(Map<OpenPgpV4Fingerprint, PGPSignature> validSignatures, Map<File, PGPPublicKeyRing> publicKeys) {
        for (OpenPgpV4Fingerprint sigKeyFp : validSignatures.keySet()) {
            PGPSignature signature = validSignatures.get(sigKeyFp);
            for (File file : publicKeys.keySet()) {
                // Search signing key ring
                PGPPublicKeyRing publicKeyRing = publicKeys.get(file);
                if (publicKeyRing.getPublicKey(sigKeyFp.getKeyId()) == null) {
                    continue;
                }

                String utcSigDate = df.format(signature.getCreationTime());
                OpenPgpV4Fingerprint primaryKeyFp = new OpenPgpV4Fingerprint(publicKeyRing);
                System.out.println(utcSigDate + " " + sigKeyFp.toString() + " " + primaryKeyFp.toString() +
                        " signed by " + file.getName());
            }
        }
    }

    private Map<File, PGPPublicKeyRing> readCertificatesFromFiles() {
        Map<File, PGPPublicKeyRing> publicKeys = new HashMap<>();
        for (File cert : certificates) {
            try(FileInputStream in = new FileInputStream(cert)) {
                publicKeys.put(cert, PGPainless.readKeyRing().publicKeyRing(in));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return publicKeys;
    }

    private Date parseNotAfter() {
        try {
            return notAfter.equals("now") ? new Date() : notAfter.equals("-") ? endOfTime : df.parse(notAfter);
        } catch (ParseException e) {
            System.out.println("Invalid date string supplied as value of --not-after.");
            System.exit(1);
            return null;
        }
    }

    private Date parseNotBefore() {
        try {
            return notBefore.equals("now") ? new Date() : notBefore.equals("-") ? beginningOfTime: df.parse(notBefore);
        } catch (ParseException e) {
            System.out.println("Invalid date string supplied as value of --not-before.");
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
