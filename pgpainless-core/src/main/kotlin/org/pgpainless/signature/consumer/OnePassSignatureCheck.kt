// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.key.SubkeyIdentifier

/**
 * Tuple-class that bundles together a [PGPOnePassSignature] object, a [PGPPublicKeyRing] destined
 * to verify the signature, the [PGPSignature] itself and a record of whether the signature was
 * verified.
 *
 * @param onePassSignature the one-pass-signature packet
 * @param verificationKeys certificate containing the signing subkey
 * @param signature the signature packet
 */
data class OnePassSignatureCheck(
    val onePassSignature: PGPOnePassSignature,
    val verificationKeys: OpenPGPCertificate,
    var signature: PGPSignature? = null
) {

    /**
     * Return an identifier for the signing key.
     *
     * @return signing key fingerprint
     */
    val signingKey: SubkeyIdentifier
        get() = SubkeyIdentifier(verificationKeys.pgpPublicKeyRing, onePassSignature.keyID)
}
