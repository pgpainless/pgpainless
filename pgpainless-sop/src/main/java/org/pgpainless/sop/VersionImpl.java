// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sop.operation.Version;

/**
 * Implementation of the <pre>version</pre> operation using PGPainless.
 */
public class VersionImpl implements Version {

    // draft version
    private static final String SOP_VERSION = "06";

    @Override
    public String getName() {
        return "PGPainless-SOP";
    }

    @Override
    public String getVersion() {
        // See https://stackoverflow.com/a/50119235
        String version;
        try {
            Properties properties = new Properties();
            InputStream propertiesFileIn = getClass().getResourceAsStream("/version.properties");
            if (propertiesFileIn == null) {
                throw new IOException("File version.properties not found.");
            }
            properties.load(propertiesFileIn);
            version = properties.getProperty("version");
        } catch (IOException e) {
            version = "DEVELOPMENT";
        }
        return version;
    }

    @Override
    public String getBackendVersion() {
        double bcVersion = new BouncyCastleProvider().getVersion();
        return String.format(Locale.US, "Bouncy Castle %.2f", bcVersion);
    }

    @Override
    public String getExtendedVersion() {
        return getName() + " " + getVersion() + "\n" +
                "https://codeberg.org/PGPainless/pgpainless/src/branch/master/pgpainless-sop\n" +
                "\n" +
                "Implementation of the Stateless OpenPGP Protocol Version " + SOP_VERSION + "\n" +
                "https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-" + SOP_VERSION + "\n" +
                "\n" +
                "Based on pgpainless-core " + getVersion() + "\n" +
                "https://pgpainless.org\n" +
                "\n" +
                "Using " + getBackendVersion() + "\n" +
                "https://www.bouncycastle.org/java.html";
    }
}
