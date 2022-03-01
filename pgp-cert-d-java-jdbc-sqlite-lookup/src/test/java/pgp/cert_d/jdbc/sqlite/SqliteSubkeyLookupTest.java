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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SqliteSubkeyLookupTest {

    private File databaseFile;
    private DatabaseSubkeyLookup lookup;

    @BeforeEach
    public void setupLookup() throws IOException, SQLException {
        databaseFile = Files.createTempFile("pgp.cert.d-", "lookup.db").toFile();
        databaseFile.createNewFile();
        databaseFile.deleteOnExit();
        lookup = new DatabaseSubkeyLookup(SqliteSubkeyLookupDaoImpl.forDatabaseFile(databaseFile));
    }

    @Test
    public void simpleInsertAndGet() throws IOException {
        store("eb85bb5fa33a75e15e944e63f231550c4f47e38e", 123L, 234L);
        store("d1a66e1a23b182c9980f788cfbfcc82a015e7330", 234L);

        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), lookup.getCertificateFingerprintsForSubkeyId(123L));
        assertEquals(
                new HashSet<>(Arrays.asList("eb85bb5fa33a75e15e944e63f231550c4f47e38e", "d1a66e1a23b182c9980f788cfbfcc82a015e7330")),
                lookup.getCertificateFingerprintsForSubkeyId(234L));
    }

    @Test
    public void getNonExistingSubkeyYieldsNull() throws IOException {
        assertTrue(lookup.getCertificateFingerprintsForSubkeyId(6666666).isEmpty());
    }

    @Test
    public void secondInstanceLookupTest() throws IOException, SQLException {
        store("eb85bb5fa33a75e15e944e63f231550c4f47e38e", 1337L);
        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), lookup.getCertificateFingerprintsForSubkeyId(1337));

        // do the lookup using a second db instance on the same file
        DatabaseSubkeyLookup secondInstance = new DatabaseSubkeyLookup(SqliteSubkeyLookupDaoImpl.forDatabaseFile(databaseFile));
        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), secondInstance.getCertificateFingerprintsForSubkeyId(1337));
    }

    @Test
    public void ignoreInsertDuplicates() throws IOException {
        store("d1a66e1a23b182c9980f788cfbfcc82a015e7330", 123L, 234L);
        // per default we ignore duplicates
        store("d1a66e1a23b182c9980f788cfbfcc82a015e7330", 123L, 512L);
    }

    private void store(String cert, long... ids) throws IOException {
        List<Long> idList = new ArrayList<>();
        for (long id : ids) {
            idList.add(id);
        }
        lookup.storeCertificateSubkeyIds(cert, idList);
    }
}
