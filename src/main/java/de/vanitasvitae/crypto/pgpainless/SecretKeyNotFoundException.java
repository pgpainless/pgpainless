package de.vanitasvitae.crypto.pgpainless;

public class SecretKeyNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    private final long keyId;

    public SecretKeyNotFoundException(long keyId) {
        super("No PGPSecretKey with id " + Long.toHexString(keyId) + " (" + keyId + ") found.");
        this.keyId = keyId;
    }

    public long getKeyId() {
        return keyId;
    }
}
