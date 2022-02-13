// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pgp.certificate_store.exception.BadNameException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class FilenameResolverTest {

    private File baseDir;
    private FilenameResolver resolver;

    @BeforeEach
    public void setup() throws IOException {
        baseDir = Files.createTempDirectory("filenameresolver").toFile();
        baseDir.deleteOnExit();
        resolver = new FilenameResolver(baseDir);
    }

    @Test
    public void testGetFileForFingerprint1() throws BadNameException {
        String fingerprint = "d1a66e1a23b182c9980f788cfbfcc82a015e7330";

        File subDir = new File(baseDir, "d1");
        File expected = new File(subDir, "a66e1a23b182c9980f788cfbfcc82a015e7330");

        assertEquals(expected.getAbsolutePath(), resolver.getCertFileByFingerprint(fingerprint).getAbsolutePath());
    }

    @Test
    public void testGetFileForFingerprint2() throws BadNameException {
        String fingerprint = "eb85bb5fa33a75e15e944e63f231550c4f47e38e";

        File subDir = new File(baseDir, "eb");
        File expected = new File(subDir, "85bb5fa33a75e15e944e63f231550c4f47e38e");

        assertEquals(expected.getAbsolutePath(), resolver.getCertFileByFingerprint(fingerprint).getAbsolutePath());
    }

    @Test
    public void testGetFileForInvalidNonHexFingerprint() {
        String invalidFingerprint = "thisisnothexadecimalthisisnothexadecimal";
        assertThrows(BadNameException.class, () -> resolver.getCertFileByFingerprint(invalidFingerprint));
    }

    @Test
    public void testGetFileForInvalidWrongLengthFingerprint() {
        String invalidFingerprint = "d1a66e1a23b182c9980f788cfbfcc82a015e73301234";
        assertThrows(BadNameException.class, () -> resolver.getCertFileByFingerprint(invalidFingerprint));
    }

    @Test
    public void testGetFileForNullFingerprint() {
        assertThrows(NullPointerException.class, () -> resolver.getCertFileByFingerprint(null));
    }

    @Test
    public void testGetFileForSpecialName() throws BadNameException {
        String specialName = "trust-root";
        File expected = new File(baseDir, "trust-root");

        assertEquals(expected, resolver.getCertFileBySpecialName(specialName));
    }

    @Test
    public void testGetFileForInvalidSpecialName() {
        String invalidSpecialName = "invalid";
        assertThrows(BadNameException.class, () -> resolver.getCertFileBySpecialName(invalidSpecialName));
    }
}
