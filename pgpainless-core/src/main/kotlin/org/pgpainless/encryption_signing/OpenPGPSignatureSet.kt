// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPSignature

class OpenPGPSignatureSet<S : OpenPGPSignature>(val signatures: List<S>) : Iterable<S> {

    fun getSignaturesBy(cert: OpenPGPCertificate): List<S> =
        signatures.filter { sig -> sig.signature.keyIdentifiers.any { cert.getKey(it) != null } }

    fun getSignaturesBy(componentKey: OpenPGPCertificate.OpenPGPComponentKey): List<S> =
        signatures.filter { sig ->
            sig.signature.keyIdentifiers.any { componentKey.keyIdentifier.matches(it) }
        }

    override fun iterator(): Iterator<S> {
        return signatures.iterator()
    }
}
