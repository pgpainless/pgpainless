// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.ecc;

import javax.annotation.Nonnull;

import org.pgpainless.key.generation.type.xdh.XDHSpec;

/**
 * Elliptic curves for use with
 * {@link org.pgpainless.key.generation.type.ecc.ecdh.ECDH}/{@link org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA}.
 * For curve25519 related curve definitions see
 * {@link XDHSpec} and {@link org.pgpainless.key.generation.type.eddsa.EdDSACurve}.
 */
public enum EllipticCurve {
    _P256("prime256v1", 256), // prime256v1 is equivalent to P-256, see https://tools.ietf.org/search/rfc4492#page-32
    _P384("secp384r1", 384), // secp384r1 is equivalent to P-384, see https://tools.ietf.org/search/rfc4492#page-32
    _P521("secp521r1", 521), // secp521r1 is equivalent to P-521, see https://tools.ietf.org/search/rfc4492#page-32
    _SECP256K1("secp256k1", 256),
    _BRAINPOOLP256R1("brainpoolP256r1", 256),
    _BRAINPOOLP384R1("brainpoolP384r1", 384),
    _BRAINPOOLP512R1("brainpoolP512r1", 512)
    ;

    private final String name;
    private final int bitStrength;

    EllipticCurve(@Nonnull String name, int bitStrength) {
        this.name = name;
        this.bitStrength = bitStrength;
    }

    public String getName() {
        return name;
    }

    public int getBitStrength() {
        return bitStrength;
    }
}
