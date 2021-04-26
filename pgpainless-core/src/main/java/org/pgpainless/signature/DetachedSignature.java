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

public class DetachedSignature {
    private final PGPSignature signature;
    private final PGPKeyRing signingKeyRing;
    private final SubkeyIdentifier signingKeyIdentifier;
    private boolean verified;

    public DetachedSignature(PGPSignature signature, PGPKeyRing signingKeyRing, SubkeyIdentifier signingKeyIdentifier) {
        this.signature = signature;
        this.signingKeyRing = signingKeyRing;
        this.signingKeyIdentifier = signingKeyIdentifier;
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

    public SubkeyIdentifier getSigningKeyIdentifier() {
        return signingKeyIdentifier;
    }

    public PGPKeyRing getSigningKeyRing() {
        return signingKeyRing;
    }

    @Deprecated
    public OpenPgpV4Fingerprint getFingerprint() {
        return signingKeyIdentifier.getSubkeyFingerprint();
    }
}
