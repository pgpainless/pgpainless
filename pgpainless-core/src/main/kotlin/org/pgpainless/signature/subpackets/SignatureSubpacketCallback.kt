// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

interface SignatureSubpacketCallback<S : BaseSignatureSubpackets> {

    /**
     * Callback method that can be used to modify the hashed subpackets of a signature.
     *
     * @param hashedSubpackets hashed subpackets
     */
    fun modifyHashedSubpackets(hashedSubpackets: S) {
        // Empty default implementation to allow for cleaner overriding
    }

    /**
     * Callback method that can be used to modify the unhashed subpackets of a signature.
     *
     * @param unhashedSubpackets unhashed subpackets
     */
    fun modifyUnhashedSubpackets(unhashedSubpackets: S) {
        // Empty default implementation to allow for cleaner overriding
    }
}
