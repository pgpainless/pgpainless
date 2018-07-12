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
package org.pgpainless.pgpainless.key.collection;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class PGPKeyRing {

    private PGPPublicKeyRing publicKeys;
    private PGPSecretKeyRing secretKeys;

    public PGPKeyRing(PGPPublicKeyRing publicKeys, PGPSecretKeyRing secretKeys) {
        this.publicKeys = publicKeys;
        this.secretKeys = secretKeys;
    }

    public PGPPublicKeyRing getPublicKeys() {
        return publicKeys;
    }

    public PGPSecretKeyRing getSecretKeys() {
        return secretKeys;
    }


}
