package de.vanitasvitae.crypto.pgpainless;

public class PublicKeyNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    private final long keyId;

    public PublicKeyNotFoundException(long keyId) {
        super("No PGPPublicKey with id " + Long.toHexString(keyId) + " (" + keyId + ") found.");
        this.keyId = keyId;
    }

    public long getKeyId() {
        return keyId;
    }
}
