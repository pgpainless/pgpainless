package org.pgpainless.key.storage;

import java.io.File;

public class CertDStore {

    private final File baseDirectory;
    private static final String STORE_NAME = "pgp.cert.d";

    public CertDStore() {
        this(getDefaultBaseDir());
    }

    public CertDStore(File baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    public File fingerprintToPrefixDir(String fingerprint) {
        String dirName = fingerprint.toLowerCase().substring(0, 2);
        return new File(baseDirectory, dirName);
    }

    public String fingerprintToCertFileName(String fingerprint) {
        String certFileName = fingerprint.toLowerCase().substring(2);
        return certFileName;
    }

    public File fingerprintToCertFile(String fingerprint) {
        File dir = fingerprintToPrefixDir(fingerprint);
        File certFile = new File(dir, fingerprintToCertFileName(fingerprint));
        return certFile;
    }

    public File getBaseDirectory() {
        return baseDirectory;
    }

    private static File getDefaultBaseDir() {
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
