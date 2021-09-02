/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.signature;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.decryption_verification.SignatureInputStream;
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
    private boolean verified;

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
     * Return true if the signature is verified.
     *
     * @return verified
     */
    public boolean isVerified() {
        return verified;
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
     * Verify the one-pass signature.
     * Note: This method only checks if the signature itself is correct.
     * It does not check if the signing key was eligible to create the signature, or if the signature is expired etc.
     * Those checks are being done by {@link SignatureInputStream.VerifySignatures}.
     *
     * @return true if the signature was verified, false otherwise
     * @throws PGPException if signature verification fails with an exception.
     */
    public boolean verify() throws PGPException {
        if (signature == null) {
            throw new IllegalStateException("No comparison signature provided.");
        }
        this.verified = getOnePassSignature().verify(signature);
        return verified;
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
