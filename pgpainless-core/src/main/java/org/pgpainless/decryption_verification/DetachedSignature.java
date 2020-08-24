package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class DetachedSignature {
    private final PGPSignature signature;
    private final OpenPgpV4Fingerprint fingerprint;
    private boolean verified;

    public DetachedSignature(PGPSignature signature, OpenPgpV4Fingerprint fingerprint) {
        this.signature = signature;
        this.fingerprint = fingerprint;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public boolean isVerified() {
        return verified;
    }

    public PGPSignature getSignature() {
        return signature;
    }

    public OpenPgpV4Fingerprint getFingerprint() {
        return fingerprint;
    }
}
