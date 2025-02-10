package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey

fun OpenPGPCertificate.getSigningKeyFor(ops: PGPOnePassSignature): OpenPGPComponentKey? =
    this.getKey(ops.keyIdentifier)
