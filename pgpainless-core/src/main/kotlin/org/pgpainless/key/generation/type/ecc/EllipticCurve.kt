// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.ecc

/**
 * Elliptic curves for use with [org.pgpainless.key.generation.type.ecc.ecdh.ECDH] and
 * [org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA]. For curve25519 related curve definitions
 * see [XDHSpec] and [org.pgpainless.key.generation.type.eddsa.EdDSACurve].
 */
enum class EllipticCurve(val curveName: String, val bitStrength: Int) {
    _P256("prime256v1", 256), // prime256v1 is equivalent to P-256, see
    // https://tools.ietf.org/search/rfc4492#page-32
    _P384(
        "secp384r1",
        384), // secp384r1 is equivalent to P-384, see https://tools.ietf.org/search/rfc4492#page-32
    _P521(
        "secp521r1",
        521), // secp521r1 is equivalent to P-521, see https://tools.ietf.org/search/rfc4492#page-32
    _BRAINPOOLP256R1("brainpoolP256r1", 256),
    _BRAINPOOLP384R1("brainpoolP384r1", 384),
    _BRAINPOOLP512R1("brainpoolP512r1", 512),
    ;

    fun getName(): String = curveName
}
