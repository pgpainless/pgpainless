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
