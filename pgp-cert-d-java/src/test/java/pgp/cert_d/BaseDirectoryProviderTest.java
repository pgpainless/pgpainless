// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class BaseDirectoryProviderTest {

    @Test
    public void testGetDefaultBaseDir_Linux() {
        assumeTrue(System.getProperty("os.name").equalsIgnoreCase("linux"));
        File baseDir = BaseDirectoryProvider.getDefaultBaseDirForOS("linux");
        assertTrue(baseDir.getAbsolutePath().endsWith("/.local/share/pgp.cert.d"));
    }
}
