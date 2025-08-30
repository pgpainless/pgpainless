// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import org.bouncycastle.bcpg.sig.RevocationReason
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets.Callback

interface RevocationSignatureSubpackets : BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<RevocationSignatureSubpackets> {
        fun then(
            nextCallback: SignatureSubpacketCallback<RevocationSignatureSubpackets>
        ): Callback {
            val currCallback = this
            return object : Callback {
                override fun modifyHashedSubpackets(
                    hashedSubpackets: RevocationSignatureSubpackets
                ) {
                    currCallback.modifyHashedSubpackets(hashedSubpackets)
                    nextCallback.modifyHashedSubpackets(hashedSubpackets)
                }

                override fun modifyUnhashedSubpackets(
                    unhashedSubpackets: RevocationSignatureSubpackets
                ) {
                    currCallback.modifyUnhashedSubpackets(unhashedSubpackets)
                    nextCallback.modifyUnhashedSubpackets(unhashedSubpackets)
                }
            }
        }
    }

    fun setRevocationReason(
        revocationAttributes: RevocationAttributes
    ): RevocationSignatureSubpackets

    fun setRevocationReason(
        isCritical: Boolean,
        revocationAttributes: RevocationAttributes
    ): RevocationSignatureSubpackets

    fun setRevocationReason(
        isCritical: Boolean,
        reason: RevocationAttributes.Reason,
        description: CharSequence
    ): RevocationSignatureSubpackets

    fun setRevocationReason(reason: RevocationReason?): RevocationSignatureSubpackets

    companion object {

        /** Factory method for a [Callback] that does nothing. */
        @JvmStatic fun nop() = object : Callback {}

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the hashed
         * subpacket area of a [RevocationSignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = RevocationSignatureSubpackets.applyHashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyHashed(function: RevocationSignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyHashedSubpackets(
                    hashedSubpackets: RevocationSignatureSubpackets
                ) {
                    function(hashedSubpackets)
                }
            }
        }

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the unhashed
         * subpacket area of a [RevocationSignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = RevocationSignatureSubpackets.applyUnhashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyUnhashed(function: RevocationSignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyUnhashedSubpackets(
                    unhashedSubpackets: RevocationSignatureSubpackets
                ) {
                    function(unhashedSubpackets)
                }
            }
        }
    }
}
