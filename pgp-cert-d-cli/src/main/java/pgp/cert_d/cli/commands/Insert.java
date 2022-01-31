// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;
import picocli.CommandLine;

@CommandLine.Command(name = "insert",
        description = "Insert or update a certificate")
public class Insert implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Insert.class);

    @Override
    public void run() {
        try {
            Certificate certificate = PGPCertDCli.getCertificateDirectory().insertCertificate(System.in, new MergeCallback() {
                @Override
                public Certificate merge(Certificate data, Certificate existing) {
                    return data;
                }
            });
            // CHECKSTYLE:OFF
            System.out.println(certificate.getFingerprint());
            // CHECKSTYLE:ON
        } catch (IOException e) {
            LOGGER.info("IO-Error", e);
            System.exit(-1);
        } catch (InterruptedException e) {
            LOGGER.info("Thread interrupted.", e);
            System.exit(-1);
        }
    }
}
