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

    /**
     * Return a new [SignatureSubpacketCallback] which first applies the current callback instance,
     * followed by the passed in [nextCallback].
     * This is useful to composite different [SignatureSubpacketCallback] instances.
     */
    fun then(nextCallback: SignatureSubpacketCallback<S>): SignatureSubpacketCallback<S> {
        val currCallback = this
        return object : SignatureSubpacketCallback<S> {
            override fun modifyHashedSubpackets(hashedSubpackets: S) {
                currCallback.modifyHashedSubpackets(hashedSubpackets)
                nextCallback.modifyHashedSubpackets(hashedSubpackets)
            }

            override fun modifyUnhashedSubpackets(unhashedSubpackets: S) {
                currCallback.modifyUnhashedSubpackets(unhashedSubpackets)
                nextCallback.modifyUnhashedSubpackets(unhashedSubpackets)
            }
        }
    }
}
