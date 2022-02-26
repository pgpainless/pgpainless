// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli;

import org.pgpainless.certificate_store.CertificateReader;
import org.pgpainless.certificate_store.SharedPGPCertificateDirectoryAdapter;
import pgp.cert_d.BaseDirectoryProvider;
import pgp.cert_d.SharedPGPCertificateDirectoryImpl;
import pgp.cert_d.cli.commands.Get;
import pgp.cert_d.cli.commands.Import;
import pgp.cert_d.cli.commands.MultiImport;
import pgp.cert_d.jdbc.sqlite.DatabaseSubkeyLookup;
import pgp.cert_d.jdbc.sqlite.SqliteSubkeyLookupDaoImpl;
import pgp.certificate_store.SubkeyLookup;
import pgp.certificate_store.exception.NotAStoreException;
import pgp.certificate_store.CertificateDirectory;
import picocli.CommandLine;

import java.io.File;
import java.sql.SQLException;

@CommandLine.Command(
        subcommands = {
                Import.class,
                MultiImport.class,
                Get.class,
        }
)
public class PGPCertDCli {

    @CommandLine.Option(names = "--base-directory", paramLabel = "DIRECTORY", description = "Overwrite the default certificate directory")
    File baseDirectory;

    private static CertificateDirectory certificateDirectory;

    private int executionStrategy(CommandLine.ParseResult parseResult) {
        try {
            initStore();
        } catch (NotAStoreException | SQLException e) {
            return -1;
        }
        return new CommandLine.RunLast().execute(parseResult);
    }

    private void initStore() throws NotAStoreException, SQLException {
        SharedPGPCertificateDirectoryImpl certificateDirectory;
        SubkeyLookup subkeyLookup;
        if (baseDirectory == null) {
            baseDirectory = BaseDirectoryProvider.getDefaultBaseDir();
        }

        certificateDirectory = new SharedPGPCertificateDirectoryImpl(
                baseDirectory,
                new CertificateReader());
        subkeyLookup = new DatabaseSubkeyLookup(
                SqliteSubkeyLookupDaoImpl.forDatabaseFile(new File(baseDirectory, "_pgpainless_subkey_map.db")));

        PGPCertDCli.certificateDirectory = new SharedPGPCertificateDirectoryAdapter(certificateDirectory, subkeyLookup);
    }

    public static void main(String[] args) {
        PGPCertDCli cli = new PGPCertDCli();
        new CommandLine(cli)
                .setExecutionStrategy(parserResult -> cli.executionStrategy(parserResult))
                .execute(args);
    }

    public static CertificateDirectory getCertificateDirectory() {
        return certificateDirectory;
    }
}
