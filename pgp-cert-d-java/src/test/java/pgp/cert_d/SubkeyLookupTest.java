// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

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
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import pgp.cert_d.jdbc.sqlite.DatabaseSubkeyLookup;
import pgp.cert_d.jdbc.sqlite.SqliteSubkeyLookupDaoImpl;
import pgp.certificate_store.SubkeyLookup;

public class SubkeyLookupTest {

    private static final List<SubkeyLookup> testSubjects = new ArrayList<>();

    @BeforeAll
    public static void setupLookupTestSubjects() throws IOException, SQLException {
        InMemorySubkeyLookup inMemorySubkeyLookup = new InMemorySubkeyLookup();
        testSubjects.add(inMemorySubkeyLookup);

        File sqliteDatabase = Files.createTempFile("subkeyLookupTest", ".db").toFile();
        sqliteDatabase.createNewFile();
        sqliteDatabase.deleteOnExit();
        DatabaseSubkeyLookup sqliteSubkeyLookup = new DatabaseSubkeyLookup(SqliteSubkeyLookupDaoImpl.forDatabaseFile(sqliteDatabase));
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

        assertTrue(subject.getCertificateFingerprintsForSubkeyId(123).isEmpty());
        assertTrue(subject.getCertificateFingerprintsForSubkeyId(1337).isEmpty());
        assertTrue(subject.getCertificateFingerprintsForSubkeyId(420).isEmpty());

        // Store one val, others still null

        subject.storeCertificateSubkeyIds("d1a66e1a23b182c9980f788cfbfcc82a015e7330", Collections.singletonList(123L));

        assertEquals(Collections.singleton("d1a66e1a23b182c9980f788cfbfcc82a015e7330"), subject.getCertificateFingerprintsForSubkeyId(123));
        assertTrue(subject.getCertificateFingerprintsForSubkeyId(1337).isEmpty());
        assertTrue(subject.getCertificateFingerprintsForSubkeyId(420).isEmpty());

        // Store other val, first stays intact

        subject.storeCertificateSubkeyIds("d1a66e1a23b182c9980f788cfbfcc82a015e7330", Collections.singletonList(1337L));
        subject.storeCertificateSubkeyIds("d1a66e1a23b182c9980f788cfbfcc82a015e7330", Collections.singletonList(420L));

        assertEquals(Collections.singleton("d1a66e1a23b182c9980f788cfbfcc82a015e7330"), subject.getCertificateFingerprintsForSubkeyId(123));
        assertEquals(Collections.singleton("d1a66e1a23b182c9980f788cfbfcc82a015e7330"), subject.getCertificateFingerprintsForSubkeyId(1337));
        assertEquals(Collections.singleton("d1a66e1a23b182c9980f788cfbfcc82a015e7330"), subject.getCertificateFingerprintsForSubkeyId(420));

        // add additional entry for subkey

        subject.storeCertificateSubkeyIds("eb85bb5fa33a75e15e944e63f231550c4f47e38e", Collections.singletonList(123L));

        assertEquals(
                new HashSet<>(Arrays.asList("eb85bb5fa33a75e15e944e63f231550c4f47e38e", "d1a66e1a23b182c9980f788cfbfcc82a015e7330")),
                subject.getCertificateFingerprintsForSubkeyId(123));
    }
}
