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
package org.pgpainless.decryption_verification;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

public interface MissingPublicKeyCallback {

    /**
     * This method gets called if we encounter a signature made by a key which was not provided for signature verification.
     * If you cannot provide the requested key, it is safe to return null here.
     * PGPainless will then continue verification with the next signature.
     *
     * Note: The key-id might belong to a subkey, so be aware that when looking up the {@link PGPPublicKeyRing},
     * you may not only search for the key-id on the key rings primary key!
     *
     * It would be super cool to provide the OpenPgp fingerprint here, but unfortunately one-pass-signatures
     * only contain the key id (see https://datatracker.ietf.org/doc/html/rfc4880#section-5.4)
     *
     * @param keyId ID of the missing signing (sub)key
     *
     * @return keyring containing the key or null
     */
    @Nullable PGPPublicKeyRing onMissingPublicKeyEncountered(@Nonnull Long keyId);

}
