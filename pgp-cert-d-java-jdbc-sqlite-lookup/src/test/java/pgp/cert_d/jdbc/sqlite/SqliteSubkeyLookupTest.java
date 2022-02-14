// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        lookup.storeIdentifierForSubkeyId(123L, "trust-root");
        lookup.storeIdentifierForSubkeyId(234L, "trust-root");
        assertEquals("trust-root", lookup.getIdentifierForSubkeyId(123L));
        assertEquals("trust-root", lookup.getIdentifierForSubkeyId(234L));
    }

    @Test
    public void getNonExistingSubkeyYieldsNull() throws IOException, SQLException {
        assertTrue(lookup.get(6666666).isEmpty());
        assertNull(lookup.getIdentifierForSubkeyId(6666666));
    }

    @Test
    public void secondInstanceLookupTest() throws IOException, SQLException {
        lookup.storeIdentifierForSubkeyId(1337, "eb85bb5fa33a75e15e944e63f231550c4f47e38e");
        assertEquals("eb85bb5fa33a75e15e944e63f231550c4f47e38e", lookup.getIdentifierForSubkeyId(1337));

        // do the lookup using a second db instance on the same file
        SqliteSubkeyLookup secondInstance = SqliteSubkeyLookup.forDatabaseFile(databaseFile);
        assertEquals("eb85bb5fa33a75e15e944e63f231550c4f47e38e", secondInstance.getIdentifierForSubkeyId(1337));
    }

    @Test
    public void specialNamesAreFavoured() throws IOException, SQLException {
        // insert 3 different entries for subkey 1234L
        lookup.storeIdentifierForSubkeyId(1234L, "eb85bb5fa33a75e15e944e63f231550c4f47e38e");
        lookup.storeIdentifierForSubkeyId(1234L, "trust-root");
        lookup.storeIdentifierForSubkeyId(1234L, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");

        List<Entry> allEntries = lookup.get(1234L);
        assertEquals(3, allEntries.size());
        for (Entry e : allEntries) {
            assertEquals(1234L, e.getSubkeyId());
        }

        // we always expect the special name to be favoured
        assertEquals("trust-root", lookup.getIdentifierForSubkeyId(1234L));
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
