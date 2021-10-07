// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
