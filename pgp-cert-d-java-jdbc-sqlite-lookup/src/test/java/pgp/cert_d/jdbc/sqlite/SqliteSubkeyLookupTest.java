// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        lookup.storeIdentifierForSubkeyId(123L, "eb85bb5fa33a75e15e944e63f231550c4f47e38e");
        lookup.storeIdentifierForSubkeyId(234L, "eb85bb5fa33a75e15e944e63f231550c4f47e38e");
        lookup.storeIdentifierForSubkeyId(234L, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");

        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), lookup.getIdentifiersForSubkeyId(123L));
        assertEquals(
                new HashSet<>(Arrays.asList("eb85bb5fa33a75e15e944e63f231550c4f47e38e", "d1a66e1a23b182c9980f788cfbfcc82a015e7330")),
                lookup.getIdentifiersForSubkeyId(234L));
    }

    @Test
    public void getNonExistingSubkeyYieldsNull() throws IOException, SQLException {
        assertTrue(lookup.get(6666666).isEmpty());
        assertTrue(lookup.getIdentifiersForSubkeyId(6666666).isEmpty());
    }

    @Test
    public void secondInstanceLookupTest() throws IOException, SQLException {
        lookup.storeIdentifierForSubkeyId(1337, "eb85bb5fa33a75e15e944e63f231550c4f47e38e");
        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), lookup.getIdentifiersForSubkeyId(1337));

        // do the lookup using a second db instance on the same file
        SqliteSubkeyLookup secondInstance = SqliteSubkeyLookup.forDatabaseFile(databaseFile);
        assertEquals(Collections.singleton("eb85bb5fa33a75e15e944e63f231550c4f47e38e"), secondInstance.getIdentifiersForSubkeyId(1337));
    }

    @Test
    public void ignoreInsertDuplicates() throws IOException {
        lookup.storeIdentifierForSubkeyId(123L, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");
        // per default we ignore duplicates
        lookup.storeIdentifierForSubkeyId(123L, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");

        // if we choose not to ignore duplicates, we raise an exception
        assertThrows(SQLException.class, () ->
                lookup.insert(123L, "d1a66e1a23b182c9980f788cfbfcc82a015e7330", false));
    }
}
