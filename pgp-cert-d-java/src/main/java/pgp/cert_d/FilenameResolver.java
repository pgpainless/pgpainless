// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.exception.BadNameException;

import java.io.File;
import java.util.regex.Pattern;

public class FilenameResolver {

    private final File baseDirectory;
    private final Pattern openPgpV4FingerprintPattern = Pattern.compile("^[a-f0-9]{40}$");

    public FilenameResolver(File baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    public File getBaseDirectory() {
        return baseDirectory;
    }

    /**
     * Calculate the file location for the certificate addressed by the given
     * lowercase hexadecimal OpenPGP fingerprint.
     *
     * @param fingerprint fingerprint
     * @return absolute certificate file location
     * @throws BadNameException
     */
    public File getCertFileByFingerprint(String fingerprint) throws BadNameException {
        if (!isFingerprint(fingerprint)) {
            throw new BadNameException();
        }

        // is fingerprint
        File subdirectory = new File(getBaseDirectory(), fingerprint.substring(0, 2));
        File file = new File(subdirectory, fingerprint.substring(2));
        return file;
    }

    public File getCertFileBySpecialName(String specialName) throws BadNameException {
        if (!isSpecialName(specialName)) {
            throw new BadNameException();
        }

        return new File(getBaseDirectory(), specialName);
    }

    private boolean isFingerprint(String fingerprint) {
        return openPgpV4FingerprintPattern.matcher(fingerprint).matches();
    }

    private boolean isSpecialName(String specialName) {
        return SpecialNames.lookupSpecialName(specialName) != null;
    }

}
