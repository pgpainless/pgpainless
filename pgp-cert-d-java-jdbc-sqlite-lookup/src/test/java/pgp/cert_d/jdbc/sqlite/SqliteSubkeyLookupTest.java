// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SqliteSubkeyLookupTest {

    private File databaseFile;
    private SqliteSubkeyLookup lookup;

    @BeforeEach
    public void setupLookup() throws IOException, SQLException {
        databaseFile = Files.createTempFile("pgp.cert.d-", "lookup.db").toFile();
        databaseFile.createNewFile();
        databaseFile.deleteOnExit();
        lookup = SqliteSubkeyLookup.forDatabaseFile(databaseFile);
    }

    @Test
    public void simpleInsertAndGet() throws IOException {
        lookup.storeCertificateSubkeyIds("eb85bb5fa33a75e15e944e63f231550c4f47e38e", Arrays.asList(123L, 234L));
        lookup.storeCertificateSubkeyIds("d1a66e1a23b182c9980f788cfbfcc82a015e7330", Collections.singletonList(234L));

        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), lookup.getCertificatesForSubkeyId(123L));
        assertEquals(
                new HashSet<>(Arrays.asList("eb85bb5fa33a75e15e944e63f231550c4f47e38e", "d1a66e1a23b182c9980f788cfbfcc82a015e7330")),
                lookup.getCertificatesForSubkeyId(234L));
    }

    @Test
    public void getNonExistingSubkeyYieldsNull() throws IOException, SQLException {
        assertTrue(lookup.selectValues(6666666).isEmpty());
        assertTrue(lookup.getCertificatesForSubkeyId(6666666).isEmpty());
    }

    @Test
    public void secondInstanceLookupTest() throws IOException, SQLException {
        lookup.storeCertificateSubkeyIds("eb85bb5fa33a75e15e944e63f231550c4f47e38e", Collections.singletonList(1337L));
        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), lookup.getCertificatesForSubkeyId(1337));

        // do the lookup using a second db instance on the same file
        SqliteSubkeyLookup secondInstance = SqliteSubkeyLookup.forDatabaseFile(databaseFile);
        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), secondInstance.getCertificatesForSubkeyId(1337));
    }

    @Test
    public void ignoreInsertDuplicates() throws IOException {
        lookup.storeCertificateSubkeyIds("d1a66e1a23b182c9980f788cfbfcc82a015e7330", Arrays.asList(123L, 234L));
        // per default we ignore duplicates
        lookup.storeCertificateSubkeyIds("d1a66e1a23b182c9980f788cfbfcc82a015e7330", Arrays.asList(123L, 512L));
    }
}
