// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli;

import org.pgpainless.certificate_store.CertificateCertificateReader;
import org.pgpainless.certificate_store.SharedPGPCertificateDirectoryAdapter;
import pgp.cert_d.SharedPGPCertificateDirectoryImpl;
import pgp.cert_d.cli.commands.Get;
import pgp.cert_d.cli.commands.Insert;
import pgp.cert_d.cli.commands.PrintDirectory;
import pgp.cert_d.exception.NotAStoreException;
import pgp.certificate_store.CertificateStore;
import picocli.CommandLine;

import java.io.File;

@CommandLine.Command(
        subcommands = {
                Insert.class,
                PrintDirectory.class,
                Get.class,
        }
)
public class PGPCertDCli {

    @CommandLine.Option(names = "--base-directory", paramLabel = "DIRECTORY", description = "Overwrite the default certificate directory")
    File baseDirectory;

    private static CertificateStore certificateStore;
    private static String baseDir;

    private int executionStrategy(CommandLine.ParseResult parseResult) {
        try {
            initStore();
        } catch (NotAStoreException e) {
            return -1;
        }
        return new CommandLine.RunLast().execute(parseResult);
    }

    private void initStore() throws NotAStoreException {
        SharedPGPCertificateDirectoryImpl certificateDirectory;
        if (baseDirectory != null) {
            certificateDirectory = new SharedPGPCertificateDirectoryImpl(
                    baseDirectory,
                    new CertificateCertificateReader());
        } else {
            certificateDirectory = new SharedPGPCertificateDirectoryImpl(
                    new CertificateCertificateReader());
        }
        baseDir = certificateDirectory.getBaseDirectory().getAbsolutePath();
        certificateStore = new SharedPGPCertificateDirectoryAdapter(certificateDirectory);
    }

    public static void main(String[] args) {
        PGPCertDCli cli = new PGPCertDCli();
        new CommandLine(cli)
                .setExecutionStrategy(parserResult -> cli.executionStrategy(parserResult))
                .execute(args);
    }

    public static CertificateStore getCertificateDirectory() {
        return certificateStore;
    }

    public static String getBaseDir() {
        return baseDir;
    }
}
