// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class KeyFlag(val flag: Int) {

    /** This key may be used to certify third-party keys. */
    CERTIFY_OTHER(1),

    /** This key may be used to sign data. */
    SIGN_DATA(2),

    /** This key may be used to encrypt communications. */
    ENCRYPT_COMMS(4),

    /** This key may be used to encrypt storage. */
    ENCRYPT_STORAGE(8),

    /** The private component of this key may have been split by a secret-sharing mechanism. */
    SPLIT(16),

    /** This key may be used for authentication. */
    AUTHENTICATION(32),

    /** The private component of this key may be in the possession of more than one person. */
    SHARED(128),
    ;

    companion object {

        /**
         * Convert a bitmask into a list of [KeyFlags][KeyFlag].
         *
         * @param bitmask bitmask
         * @return list of key flags encoded by the bitmask
         */
        @JvmStatic
        fun fromBitmask(bitmask: Int): List<KeyFlag> {
            return values().filter { it.flag and bitmask != 0 }
        }

        /**
         * Encode a list of [KeyFlags][KeyFlag] into a bitmask.
         *
         * @param flags list of flags
         * @return bitmask
         */
        @JvmStatic
        fun toBitmask(vararg flags: KeyFlag): Int {
            return flags.map { it.flag }.reduceOrNull { mask, f -> mask or f } ?: 0
        }

        /**
         * Return true if the provided bitmask has the bit for the provided flag set. Return false
         * if the mask does not contain the flag.
         *
         * @param mask bitmask
         * @param flag flag to be tested for
         * @return true if flag is set, false otherwise
         */
        @JvmStatic
        fun hasKeyFlag(mask: Int, flag: KeyFlag): Boolean {
            return mask and flag.flag == flag.flag
        }

        @JvmStatic
        fun containsAny(mask: Int, vararg flags: KeyFlag): Boolean {
            return flags.any { hasKeyFlag(mask, it) }
        }
    }
}
