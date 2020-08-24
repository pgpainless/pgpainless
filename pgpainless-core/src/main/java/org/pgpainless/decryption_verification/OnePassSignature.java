package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class OnePassSignature {
    private final PGPOnePassSignature onePassSignature;
    private final OpenPgpV4Fingerprint fingerprint;
    private PGPSignature signature;
    private boolean verified;

    public OnePassSignature(PGPOnePassSignature onePassSignature, OpenPgpV4Fingerprint fingerprint) {
        this.onePassSignature = onePassSignature;
        this.fingerprint = fingerprint;
    }

    public boolean isVerified() {
        return verified;
    }

    public PGPOnePassSignature getOnePassSignature() {
        return onePassSignature;
    }

    public OpenPgpV4Fingerprint getFingerprint() {
        return fingerprint;
    }

    public boolean verify(PGPSignature signature) throws PGPException {
        this.verified = getOnePassSignature().verify(signature);
        if (verified) {
            this.signature = signature;
        }
        return verified;
    }

    public PGPSignature getSignature() {
        return signature;
    }
}
