// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Tuple-class which bundles together a signature, the signing key that created the signature,
 * an identifier of the signing key and a record of whether the signature was verified.
 */
public class DetachedSignatureCheck {
    private final PGPSignature signature;
    private final PGPKeyRing signingKeyRing;
    private final SubkeyIdentifier signingKeyIdentifier;

    /**
     * Create a new {@link DetachedSignatureCheck} object.
     *
     * @param signature signature
     * @param signingKeyRing signing key that created the signature
     * @param signingKeyIdentifier identifier of the used signing key
     */
    public DetachedSignatureCheck(PGPSignature signature, PGPKeyRing signingKeyRing, SubkeyIdentifier signingKeyIdentifier) {
        this.signature = signature;
        this.signingKeyRing = signingKeyRing;
        this.signingKeyIdentifier = signingKeyIdentifier;
    }

    /**
     * Return the OpenPGP signature.
     *
     * @return signature
     */
    public PGPSignature getSignature() {
        return signature;
    }

    /**
     * Return an identifier pointing to the exact signing key which was used to create this signature.
     *
     * @return signing key identifier
     */
    public SubkeyIdentifier getSigningKeyIdentifier() {
        return signingKeyIdentifier;
    }

    /**
     * Return the key ring that contains the signing key that created this signature.
     *
     * @return key ring
     */
    public PGPKeyRing getSigningKeyRing() {
        return signingKeyRing;
    }

    /**
     * Return the {@link OpenPgpFingerprint} of the key that created the signature.
     *
     * @return fingerprint of the signing key
     * @deprecated use {@link #getSigningKeyIdentifier()} instead.
     */
    @Deprecated
    public OpenPgpFingerprint getFingerprint() {
        return signingKeyIdentifier.getSubkeyFingerprint();
    }
}
