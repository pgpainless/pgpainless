// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import pgp.cert_d.jdbc.sqlite.SqliteSubkeyLookup;
import pgp.certificate_store.SubkeyLookup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SubkeyLookupTest {

    private static final List<SubkeyLookup> testSubjects = new ArrayList<>();

    @BeforeAll
    public static void setupLookupTestSubjects() throws IOException, SQLException {
        InMemorySubkeyLookup inMemorySubkeyLookup = new InMemorySubkeyLookup();
        testSubjects.add(inMemorySubkeyLookup);

        File sqliteDatabase = Files.createTempFile("subkeyLookupTest", ".db").toFile();
        sqliteDatabase.createNewFile();
        sqliteDatabase.deleteOnExit();
        SqliteSubkeyLookup sqliteSubkeyLookup = SqliteSubkeyLookup.forDatabaseFile(sqliteDatabase);
        testSubjects.add(sqliteSubkeyLookup);
    }

    @AfterAll
    public static void tearDownLookupTestSubjects() {
        ((InMemorySubkeyLookup) testSubjects.get(0)).clear();
    }

    private static Stream<SubkeyLookup> provideSubkeyLookupsForTest() {
        return testSubjects.stream();
    }

    @ParameterizedTest
    @MethodSource("provideSubkeyLookupsForTest")
    public void testInsertGet(SubkeyLookup subject) throws IOException {
        // Initially all null

        assertNull(subject.getIdentifierForSubkeyId(123));
        assertNull(subject.getIdentifierForSubkeyId(1337));
        assertNull(subject.getIdentifierForSubkeyId(420));

        // Store one val, others still null

        subject.storeIdentifierForSubkeyId(123, "trust-root");

        assertEquals("trust-root", subject.getIdentifierForSubkeyId(123));
        assertNull(subject.getIdentifierForSubkeyId(1337));
        assertNull(subject.getIdentifierForSubkeyId(420));

        // Store other val, first stays intact

        subject.storeIdentifierForSubkeyId(1337, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");
        subject.storeIdentifierForSubkeyId(420, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");

        assertEquals("trust-root", subject.getIdentifierForSubkeyId(123));
        assertEquals("d1a66e1a23b182c9980f788cfbfcc82a015e7330", subject.getIdentifierForSubkeyId(1337));
        assertEquals("d1a66e1a23b182c9980f788cfbfcc82a015e7330", subject.getIdentifierForSubkeyId(420));

        // overwrite existing

        subject.storeIdentifierForSubkeyId(123, "d1a66e1a23b182c9980f788cfbfcc82a015e7330");

        // TODO: Decide on expected result and fix test
        // assertEquals("d1a66e1a23b182c9980f788cfbfcc82a015e7330", subject.getIdentifierForSubkeyId(123));
    }
}
