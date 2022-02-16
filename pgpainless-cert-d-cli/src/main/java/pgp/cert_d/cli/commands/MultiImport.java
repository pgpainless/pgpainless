// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.pgpainless.PGPainless;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;
import pgp.certificate_store.exception.BadDataException;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.IOException;

@CommandLine.Command(name = "multi-import",
        description = "Import or update multiple certificates")
public class MultiImport implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(MultiImport.class);

    // TODO: Replace with proper merge callback
    private final MergeCallback dummyMerge = new MergeCallback() {
        @Override
        public Certificate merge(Certificate data, Certificate existing) throws IOException {
            return data;
        }
    };

    @Override
    public void run() {
        try {
            PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing().publicKeyRingCollection(System.in);
            for (PGPPublicKeyRing cert : certificates) {
                ByteArrayInputStream certIn = new ByteArrayInputStream(cert.getEncoded());
                Certificate certificate = PGPCertDCli.getCertificateDirectory()
                        .insertCertificate(certIn, dummyMerge);
                // CHECKSTYLE:OFF
                System.out.println(certificate.getFingerprint());
                // CHECKSTYLE:ON
            }
        } catch (IOException e) {
            LOGGER.error("IO-Error.", e);
            System.exit(-1);
        } catch (InterruptedException e) {
            LOGGER.error("Thread interrupted.", e);
            System.exit(-1);
        } catch (BadDataException e) {
            LOGGER.error("Certificate contains bad data.", e);
            System.exit(-1);
        } catch (PGPException e) {
            LOGGER.error("PGP Exception.", e);
            System.exit(-1);
        }
    }
}
