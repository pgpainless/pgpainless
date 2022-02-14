// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

public class SpecialNameFingerprintComparatorTest {

    String fp1 = "eb85bb5fa33a75e15e944e63f231550c4f47e38e";
    String fp2 = "d1a66e1a23b182c9980f788cfbfcc82a015e7330";
    String specialName = "trust-root";
    String invalidButSpecialName = "invalid";
    SpecialNameFingerprintComparator comparator = new SpecialNameFingerprintComparator();

    @Test
    public void testFingerprintGreaterThanSpecialName() {
        assertTrue(comparator.compare(fp1, specialName) > 0);
        assertTrue(comparator.compare(fp2, specialName) > 0);
        assertTrue(comparator.compare(fp1, invalidButSpecialName) > 0);
        assertTrue(comparator.compare(fp2, invalidButSpecialName) > 0);
    }

    @Test
    public void testSpecialNameLessThanFingerprint() {
        assertTrue(comparator.compare(specialName, fp1) < 0);
        assertTrue(comparator.compare(specialName,fp2) < 0);
        assertTrue(comparator.compare(invalidButSpecialName, fp1) < 0);
        assertTrue(comparator.compare(invalidButSpecialName, fp2) < 0);
    }

    @Test
    public void testSortingList() {
        // Expected: special names first, fingerprints after that
        List<String> expected = Arrays.asList(invalidButSpecialName, specialName, fp2, fp1, fp1);
        List<String> list = new ArrayList<>();
        list.add(fp1);
        list.add(specialName);
        list.add(fp1);
        list.add(fp2);
        list.add(invalidButSpecialName);

        list.sort(new SpecialNameFingerprintComparator());

        assertEquals(expected, list);
    }

    @Test
    public void fingerprintsAreSortedLexicographically() {
        assertTrue(comparator.compare(fp1, fp2) > 0);
        assertEquals(0, comparator.compare(fp1, fp1));
        assertTrue(comparator.compare(fp2, fp1) < 0);
    }

    @Test
    public void specialNamesAreSortedLexicographically() {
        assertTrue(comparator.compare(invalidButSpecialName, specialName) < 0);
        assertEquals(0, comparator.compare(invalidButSpecialName, invalidButSpecialName));
        assertEquals(0, comparator.compare(specialName, specialName));
        assertTrue(comparator.compare(specialName, invalidButSpecialName) > 0);
    }

    @Test
    public void specialNamesAreAlwaysSmallerFingerprints() {
        assertTrue(comparator.compare(invalidButSpecialName, fp1) < 0);
        assertTrue(comparator.compare(specialName, fp1) < 0);
        assertTrue(comparator.compare(fp2, specialName) > 0);

        // upper case fingerprint is considered special name, since fingerprints are expected to be lower case
        assertTrue(comparator.compare("D1A66E1A23B182C9980F788CFBFCC82A015E7330", fp1) < 0);
        assertTrue(comparator.compare("D1A66E1A23B182C9980F788CFBFCC82A015E7330", fp2) < 0);

        assertTrue(comparator.compare("-1A66E1A23B182C9980F788CFBFCC82A015E7330", fp1) < 0);
        assertTrue(comparator.compare(":1A66E1A23B182C9980F788CFBFCC82A015E7330", fp1) < 0);
    }
}
