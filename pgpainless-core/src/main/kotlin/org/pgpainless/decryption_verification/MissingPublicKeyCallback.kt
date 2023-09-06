// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.openpgp.PGPPublicKeyRing

fun interface MissingPublicKeyCallback {

    /**
     * This method gets called if we encounter a signature made by a key which was not provided for signature verification.
     * If you cannot provide the requested key, it is safe to return null here.
     * PGPainless will then continue verification with the next signature.
     *
     * Note: The key-id might belong to a subkey, so be aware that when looking up the [PGPPublicKeyRing],
     * you may not only search for the key-id on the key rings primary key!
     *
     * It would be super cool to provide the OpenPgp fingerprint here, but unfortunately one-pass-signatures
     * only contain the key id.
     *
     * @param keyId ID of the missing signing (sub)key
     * @return keyring containing the key or null
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.4">RFC</a>
     */
    fun onMissingPublicKeyEncountered(keyId: Long): PGPPublicKeyRing?
}