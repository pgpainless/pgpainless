// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.key.SubkeyIdentifier

/**
 * Tuple-class which bundles together a signature, the signing key that created the signature, an
 * identifier of the signing key and a record of whether the signature was verified.
 *
 * @param signature OpenPGP signature
 * @param signingKeyIdentifier identifier pointing to the exact signing key which was used to create
 *   the signature
 * @param signingKeyRing certificate or key ring that contains the signing key that created the
 *   signature
 */
data class SignatureCheck(
    val signature: PGPSignature,
    val signingKeyRing: PGPKeyRing,
    val signingKeyIdentifier: SubkeyIdentifier
) {}
