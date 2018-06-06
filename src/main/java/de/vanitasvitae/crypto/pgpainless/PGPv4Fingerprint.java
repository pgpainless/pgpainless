package de.vanitasvitae.crypto.pgpainless;

import java.util.Arrays;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class PGPv4Fingerprint {

    private final byte[] fingerprintBytes;

    public PGPv4Fingerprint(PGPPublicKey publicKey) {
        if (publicKey.getVersion() != 4) {
            throw new IllegalArgumentException("PublicKey is not a OpenPGP v4 Public Key.");
        }
        this.fingerprintBytes = publicKey.getFingerprint();
    }

    public PGPv4Fingerprint(PGPSecretKey secretKey) {
        this(secretKey.getPublicKey());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (!(o instanceof PGPv4Fingerprint)) {
            return false;
        }

        return Arrays.equals(fingerprintBytes, ((PGPv4Fingerprint) o).fingerprintBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(fingerprintBytes);
    }
}
