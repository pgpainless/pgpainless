// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Tuple-class that bundles together a {@link PGPOnePassSignature} object, a {@link PGPPublicKeyRing}
 * destined to verify the signature, the {@link PGPSignature} itself and a record of whether the signature
 * was verified.
 */
public class OnePassSignatureCheck {
    private final PGPOnePassSignature onePassSignature;
    private final PGPPublicKeyRing verificationKeys;
    private PGPSignature signature;

    /**
     * Create a new {@link OnePassSignatureCheck}.
     *
     * @param onePassSignature one-pass signature packet used to initialize the signature verifier.
     * @param verificationKeys verification keys
     */
    public OnePassSignatureCheck(PGPOnePassSignature onePassSignature, PGPPublicKeyRing verificationKeys) {
        this.onePassSignature = onePassSignature;
        this.verificationKeys = verificationKeys;
    }

    public void setSignature(PGPSignature signature) {
        this.signature = signature;
    }

    /**
     * Return the {@link PGPOnePassSignature} object.
     *
     * @return onePassSignature
     */
    public PGPOnePassSignature getOnePassSignature() {
        return onePassSignature;
    }

    /**
     * Return the {@link OpenPgpV4Fingerprint} of the signing key.
     *
     * @return signing key fingerprint
     */
    public SubkeyIdentifier getSigningKey() {
        return new SubkeyIdentifier(verificationKeys, onePassSignature.getKeyID());
    }

    /**
     * Return the signature.
     *
     * @return signature
     */
    public PGPSignature getSignature() {
        return signature;
    }

    /**
     * Return the key ring used to verify the signature.
     *
     * @return verification keys
     */
    public PGPPublicKeyRing getVerificationKeys() {
        return verificationKeys;
    }
}
