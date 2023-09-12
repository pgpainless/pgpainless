// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.openpgp.PGPPublicKey
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.type.eddsa.EdDSACurve

/**
 * For secret keys of types [PublicKeyAlgorithm.ECDSA], [PublicKeyAlgorithm.ECDH] and [PublicKeyAlgorithm.EDDSA],
 * this method returns the name of the underlying elliptic curve.
 *
 * For other key types or unknown curves, this method throws an [IllegalArgumentException].
 *
 * @return curve name
 */
fun PGPPublicKey.getCurveName(): String {
    PublicKeyAlgorithm.requireFromId(algorithm)
            .let {
                when (it) {
                    PublicKeyAlgorithm.ECDSA -> publicKeyPacket.key as ECDSAPublicBCPGKey
                    PublicKeyAlgorithm.ECDH -> publicKeyPacket.key as ECDHPublicBCPGKey
                    PublicKeyAlgorithm.EDDSA -> publicKeyPacket.key as EdDSAPublicBCPGKey
                    else -> throw IllegalArgumentException("No an elliptic curve public key ($it).")
                }
            }
            .let { if (it.curveOID == GNUObjectIdentifiers.Ed25519) return EdDSACurve._Ed25519.curveName else it.curveOID}
            .let { it to ECUtil.getCurveName(it) }
            .let { if (it.second != null) return it.second else throw IllegalArgumentException("Unknown curve: ${it.first}") }
}

/**
 * Return the [PublicKeyAlgorithm] of this key.
 */
val PGPPublicKey.publicKeyAlgorithm: PublicKeyAlgorithm
    get() = PublicKeyAlgorithm.requireFromId(algorithm)

/**
 * Return the [OpenPgpFingerprint] of this key.
 */
val PGPPublicKey.openPgpFingerprint: OpenPgpFingerprint
    get() = OpenPgpFingerprint.of(this)
