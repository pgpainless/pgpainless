// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * An enumeration of features that may be set in the feature subpacket.
 *
 * See [RFC4880: Features](https://tools.ietf.org/html/rfc4880#section-5.2.3.24) See
 * [crypto-refresh: Features](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-features)
 * See
 * [LibrePGP: Features](https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-features)
 */
enum class Feature(val featureId: Byte) {

    /**
     * Support for Symmetrically Encrypted Integrity Protected Data Packets (version 1) using
     * Modification Detection Code Packets.
     *
     * See
     * [RFC-4880 §5.14: Modification Detection Code Packet](https://tools.ietf.org/html/rfc4880#section-5.14)
     * See
     * [Crypto-Refresh: Features](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-features)
     */
    MODIFICATION_DETECTION(0x01),

    /**
     * Support for OCB Encrypted Data (AEAD) as defined in LibrePGP (NON-STANDARD!) If a key
     * announces this feature, it signals support for consuming OCB Encrypted Data Packets.
     *
     * NOTE: PGPAINLESS DOES NOT YET SUPPORT THIS FEATURE!!! NOTE: This value is currently RESERVED.
     *
     * See
     * [LibrePGP: OCB Encrypted Data Packet](https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-features)
     */
    LIBREPGP_OCB_ENCRYPTED_DATA(0x02),

    /**
     * If a key announces this feature, it is a version 5 public key as defined in LibrePGP
     * (NON-STANDARD!). The version 5 format is similar to the version 4 format except for the
     * addition of a count for the key material. This count helps to parse secret key packets (which
     * are an extension of the public key packet format) in the case of an unknown algorithm. In
     * addition, fingerprints of version 5 keys are calculated differently from version 4 keys.
     *
     * NOTE: PGPAINLESS DOES NOT YET SUPPORT THIS FEATURE!!! NOTE: This value is currently RESERVED.
     *
     * See
     * [LibrePGP: Version 5 Public-Key Format](https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-features)
     */
    LIBREPGP_VERSION_5_PUBLIC_KEY(0x04),

    /**
     * Support for Symmetrically Encrypted Integrity Protected Data packet version 2. This packet
     * protects data using AEAD encryption as defined in crypto-refresh.
     *
     * See
     * [crypto-refresh-06 §5.13.2. Version 2 Sym. Encrypted Integrity Protected Data Packet Format](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-06.html#version-two-seipd)
     * See
     * [crypto-refresh: Features](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-features)
     */
    MODIFICATION_DETECTION_2(0x08),
    ;

    companion object {
        @JvmStatic
        fun fromId(id: Byte): Feature? {
            return values().firstOrNull { f -> f.featureId == id }
        }

        @JvmStatic
        fun requireFromId(id: Byte): Feature {
            return fromId(id) ?: throw NoSuchElementException("Unknown feature id encountered: $id")
        }

        @JvmStatic
        fun fromBitmask(bitmask: Int): List<Feature> {
            return values().filter { it.featureId.toInt() and bitmask != 0 }
        }

        @JvmStatic
        fun toBitmask(vararg features: Feature): Byte {
            return features
                .map { it.featureId.toInt() }
                .reduceOrNull { mask, f -> mask or f }
                ?.toByte()
                ?: 0
        }
    }
}
