// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.File;
import java.nio.file.Paths;

public class BaseDirectoryProvider {

    public static File getDefaultBaseDir() {
        // Check for environment variable
        String baseDirFromEnv = System.getenv("PGP_CERT_D");
        if (baseDirFromEnv != null) {
            return new File(baseDirFromEnv);
        }

        // return OS-specific default dir
        String osName = System.getProperty("os.name", "generic")
                .toLowerCase();
        return getDefaultBaseDirForOS(osName);
    }

    public static File getDefaultBaseDirForOS(String osName) {
        String STORE_NAME = "pgp.cert.d";
        if (osName.contains("win")) {
            // %APPDATA%\Roaming\pgp.cert.d
            return Paths.get(System.getenv("APPDATA"), "Roaming", STORE_NAME).toFile();
        }

        if (osName.contains("nux")) {
            // $XDG_DATA_HOME/pgp.cert.d
            String xdg_data_home = System.getenv("XDG_DATA_HOME");
            if (xdg_data_home != null) {
                return Paths.get(xdg_data_home, STORE_NAME).toFile();
            }
            // $HOME/.local/share/pgp.cert.d
            return Paths.get(System.getProperty("user.home"), ".local", "share", STORE_NAME).toFile();
        }

        if (osName.contains("mac")) {
            return Paths.get(System.getenv("HOME"), "Library", "Application Support", STORE_NAME).toFile();
        }

        throw new IllegalArgumentException("Unknown OS " + osName);
    }

}
