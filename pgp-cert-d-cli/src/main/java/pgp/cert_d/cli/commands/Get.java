// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import java.io.IOException;

import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.Certificate;
import picocli.CommandLine;

@CommandLine.Command(name = "get",
        description = "Retrieve certificates from the store")
public class Get implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Get.class);

    @CommandLine.Parameters(
            paramLabel = "IDENTIFIER",
            arity = "1",
            description = "Certificate identifier (fingerprint or special name)"
    )
    String identifer;

    @Override
    public void run() {
        try {
            Certificate certificate = PGPCertDCli.getCertificateDirectory()
                    .getCertificate(identifer);
            if (certificate == null) {
                return;
            }
            Streams.pipeAll(certificate.getInputStream(), System.out);
        } catch (IOException e) {
            LOGGER.info("IO Error", e);
            System.exit(-1);
        }
    }
}
