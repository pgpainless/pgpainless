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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

@CommandLine.Command(name = "verify")
public class Verify implements Runnable {

    @CommandLine.Parameters(index = "0", description = "The detached signature")
    File signature;

    @CommandLine.Parameters(index = "1..*")
    File[] certs;

    TimeZone tz = TimeZone.getTimeZone("UTC");
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");

    @Override
    public void run() {
        df.setTimeZone(tz);

        if (certs.length == 0) {
            System.out.println("No certificates supplied.");
            System.exit(19);
        }

        Map<File, PGPPublicKeyRing> publicKeys = new HashMap<>();
        for (File cert : certs) {
            try(FileInputStream in = new FileInputStream(cert)) {
                publicKeys.put(cert, PGPainless.readKeyRing().publicKeyRing(in));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try(FileInputStream sigIn = new FileInputStream(signature)) {
            DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                    .onInputStream(System.in)
                    .doNotDecrypt()
                    .verifyDetachedSignature(sigIn)
                    .verifyWith(new HashSet<>(publicKeys.values()))
                    .ignoreMissingPublicKeys()
                    .build();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.pipeAll(verifier, out);
            verifier.close();

            OpenPgpMetadata metadata = verifier.getResult();

            for (OpenPgpV4Fingerprint sigKeyFp : metadata.getVerifiedSignatures().keySet()) {
                PGPSignature signature = metadata.getVerifiedSignatures().get(sigKeyFp);
                for (File file : certs) {
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

            if (metadata.getVerifiedSignatures().isEmpty()) {
                System.out.println("Signature validation failed.");
                System.exit(3);
            }
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }
}
