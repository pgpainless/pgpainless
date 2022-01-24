// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.File;

public class OSUtil {

    public static File getDefaultBaseDir() {
        // Check for environment variable
        String baseDirFromEnv = System.getenv("PGP_CERT_D");
        if (baseDirFromEnv != null) {
            return new File(baseDirFromEnv);
        }

        // return OS-specific default dir
        String osName = System.getProperty("os.name", "generic")
                .toLowerCase();
        return getDefaultBaseDirForOS(osName, File.separator);
    }

    public static File getDefaultBaseDirForOS(String osName, String separator) {
        String STORE_NAME = "pgp.cert.d";
        if (osName.contains("win")) {
            String appData = System.getenv("APPDATA");
            String roaming = appData + separator + "Roaming";
            return new File(roaming, STORE_NAME);
        }

        if (osName.contains("nux")) {
            String xdg_data_home = System.getenv("XDG_DATA_HOME");
            String rootPath = xdg_data_home;
            if (xdg_data_home == null) {
                rootPath = System.getProperty("user.home") + separator + ".local" + separator + "share";
            }
            return new File(rootPath, STORE_NAME);
        }

        if (osName.contains("mac")) {
            String home = System.getenv("HOME");
            return new File(home + separator + "Library" + separator + "Application Support", STORE_NAME);
        }

        throw new IllegalArgumentException("Unknown OS " + osName);
    }

}
