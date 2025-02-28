// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.pgpainless.bouncycastle.extensions.getSigningKeyFor
import org.pgpainless.key.SubkeyIdentifier

/**
 * Tuple-class that bundles together a [PGPOnePassSignature] object, an [OpenPGPCertificate]
 * destined to verify the signature.
 *
 * @param onePassSignature the one-pass-signature packet
 * @param verificationKeys certificate containing the signing subkey
 */
data class OnePassSignatureCheck(
    val onePassSignature: PGPOnePassSignature,
    val verificationKeys: OpenPGPCertificate
) {

    var signature: PGPSignature? = null

    constructor(
        onePassSignature: PGPOnePassSignature,
        verificationKey: OpenPGPComponentKey
    ) : this(onePassSignature, verificationKey.certificate)

    val signingKey: OpenPGPComponentKey? = verificationKeys.getSigningKeyFor(onePassSignature)

    /**
     * Return an identifier for the signing key.
     *
     * @return signing key fingerprint
     */
    val signingKeyIdentifier: SubkeyIdentifier?
        get() = signingKey?.let { SubkeyIdentifier(it) }
}
