/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
    _P256("prime256v1"), // prime256v1 is equivalent to P-256, see https://tools.ietf.org/search/rfc4492#page-32
    _P384("secp384r1"), // secp384r1 is equivalent to P-384, see https://tools.ietf.org/search/rfc4492#page-32
    _P521("secp521r1"), // secp521r1 is equivalent to P-521, see https://tools.ietf.org/search/rfc4492#page-32
    _SECP256K1("secp256k1"),
    _BRAINPOOLP256R1("brainpoolP256r1"),
    _BRAINPOOLP384R1("brainpoolP384r1"),
    _BRAINPOOLP512R1("brainpoolP512r1")
    ;

    private final String name;

    EllipticCurve(@Nonnull String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
