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

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Tuple-class which bundles together a signature, the signing key that created the signature,
 * an identifier of the signing key and a record of whether or not the signature was verified.
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
     * Return the {@link OpenPgpV4Fingerprint} of the key that created the signature.
     *
     * @return fingerprint of the signing key
     * @deprecated use {@link #getSigningKeyIdentifier()} instead.
     */
    @Deprecated
    public OpenPgpV4Fingerprint getFingerprint() {
        return signingKeyIdentifier.getSubkeyFingerprint();
    }
}
