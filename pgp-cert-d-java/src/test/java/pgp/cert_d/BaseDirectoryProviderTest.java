// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class BaseDirectoryProviderTest {

    @Test
    public void testGetDefaultBaseDir_Linux() {
        assumeTrue(System.getProperty("os.name").equalsIgnoreCase("linux"));
        File baseDir = BaseDirectoryProvider.getDefaultBaseDirForOS("linux");
        assertTrue(baseDir.getAbsolutePath().endsWith("/.local/share/pgp.cert.d"));
    }

    @Test
    public void testGetDefaultBaseDir_Windows() {
        assumeTrue(System.getProperty("os.name").toLowerCase().contains("win"));
        File baseDir = BaseDirectoryProvider.getDefaultBaseDirForOS("Windows");
        assertTrue(baseDir.getAbsolutePath().endsWith("\\Roaming\\pgp.cert.d"));
    }

    @Test
    public void testGetDefaultBaseDir_Mac() {
        assumeTrue(System.getProperty("os.name").toLowerCase().contains("mac"));
        File baseDir = BaseDirectoryProvider.getDefaultBaseDirForOS("Mac");
        assertTrue(baseDir.getAbsolutePath().endsWith("/Library/Application Support/pgp.cert.d"));
    }

    @Test
    public void testGetDefaultBaseDirNotNull() {
        File baseDir = BaseDirectoryProvider.getDefaultBaseDir();
        assertNotNull(baseDir);
    }
}
