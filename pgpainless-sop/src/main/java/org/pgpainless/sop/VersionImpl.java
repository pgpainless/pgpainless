// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sop.operation.Version;

public class VersionImpl implements Version {

    // draft version
    private static final String SOP_VERSION = "3";

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
        return String.format("Bouncy Castle %,.2f", bcVersion);
    }

    @Override
    public String getExtendedVersion() {
        return getName() + " " + getVersion() + "\n" +
                "Based on PGPainless " + getVersion() + "\n" +
                "Using " + getBackendVersion() + "\n" +
                "See https://pgpainless.org\n" +
                "Implementation of the Stateless OpenPGP Protocol Version " + SOP_VERSION + "\n" +
                "See https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-03";
    }
}
