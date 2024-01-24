// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

interface CertificationSubpackets : BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<CertificationSubpackets>

    companion object {

        /** Factory method for a [Callback] that does nothing. */
        @JvmStatic fun nop() = object : Callback {}

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the hashed
         * subpacket area of a [CertificationSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = CertificationSubpackets.applyHashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyHashed(function: CertificationSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                    function(hashedSubpackets)
                }
            }
        }

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the unhashed
         * subpacket area of a [CertificationSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = CertificationSubpackets.applyUnhashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyUnhashed(function: CertificationSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyUnhashedSubpackets(unhashedSubpackets: CertificationSubpackets) {
                    function(unhashedSubpackets)
                }
            }
        }
    }
}
