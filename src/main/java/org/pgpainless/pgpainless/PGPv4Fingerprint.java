/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.pgpainless;

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
