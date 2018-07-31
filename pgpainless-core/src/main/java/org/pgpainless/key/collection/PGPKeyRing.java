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
package org.pgpainless.key.collection;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class PGPKeyRing {

    private PGPPublicKeyRing publicKeys;
    private PGPSecretKeyRing secretKeys;

    public PGPKeyRing(@Nonnull PGPPublicKeyRing publicKeys, @Nonnull PGPSecretKeyRing secretKeys) {

        if (publicKeys.getPublicKey().getKeyID() != secretKeys.getPublicKey().getKeyID()) {
            throw new IllegalArgumentException("publicKeys and secretKeys must have the same master key.");
        }

        this.publicKeys = publicKeys;
        this.secretKeys = secretKeys;
    }

    public PGPKeyRing(@Nonnull PGPPublicKeyRing publicKeys) {
        this.publicKeys = publicKeys;
    }

    public PGPKeyRing(@Nonnull PGPSecretKeyRing secretKeys) {
        this.secretKeys = secretKeys;
    }

    public long getKeyId() {
        return getMasterKey().getKeyID();
    }

    public @Nonnull PGPPublicKey getMasterKey() {
        PGPPublicKey publicKey = hasSecretKeys() ? secretKeys.getPublicKey() : publicKeys.getPublicKey();
        if (!publicKey.isMasterKey()) {
            throw new IllegalStateException("Expected master key is not a master key");
        }
        return publicKey;
    }

    public @Nonnull OpenPgpV4Fingerprint getV4Fingerprint() {
        return new OpenPgpV4Fingerprint(getMasterKey());
    }

    public boolean hasSecretKeys() {
        return secretKeys != null;
    }

    public @Nullable PGPPublicKeyRing getPublicKeys() {
        return publicKeys;
    }

    public @Nullable PGPSecretKeyRing getSecretKeys() {
        return secretKeys;
    }
}
