package de.vanitasvitae.crypto.pgpainless;

import org.bouncycastle.openpgp.PGPException;

public class PublicKeyNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    private long keyId;

    public PublicKeyNotFoundException(long keyId) {
        super("No PGPPublicKey with id " + Long.toHexString(keyId) + " (" + keyId + ") found.");
        this.keyId = keyId;
    }

    public PublicKeyNotFoundException(PGPException e) {

    }

    public long getKeyId() {
        return keyId;
    }
}
