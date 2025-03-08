// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import java.net.URI
import org.bouncycastle.bcpg.FingerprintUtil
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey

class OpenPgpV4Fingerprint : OpenPgpFingerprint {

    constructor(fingerprint: String) : super(fingerprint)

    constructor(bytes: ByteArray) : super(bytes)

    constructor(key: OpenPGPCertificate) : super(key.fingerprint)

    constructor(key: OpenPGPComponentKey) : super(key.pgpPublicKey)

    constructor(key: PGPPublicKey) : super(key)

    constructor(key: PGPSecretKey) : super(key)

    constructor(keys: PGPKeyRing) : super(keys)

    override fun getVersion() = 4

    override val keyId: Long = FingerprintUtil.keyIdFromV4Fingerprint(bytes)

    override val keyIdentifier: KeyIdentifier = KeyIdentifier(bytes)

    override fun isValid(fingerprint: String): Boolean {
        return fingerprint.matches("^[0-9A-F]{40}$".toRegex())
    }

    fun toUri(): URI = URI(SCHEME, toString(), null)

    override fun prettyPrint(): String {
        return buildString {
            for (i in 0..4) {
                append(fingerprint, i * 4, (i + 1) * 4).append(' ')
            }
            append(' ')
            for (i in 5..8) {
                append(fingerprint, i * 4, (i + 1) * 4).append(' ')
            }
            append(fingerprint, 36, 40)
        }
    }

    companion object {
        @JvmStatic val SCHEME = "openpgp4fpr"

        @JvmStatic
        fun fromUri(uri: URI): OpenPgpV4Fingerprint {
            if (SCHEME != uri.scheme) {
                throw IllegalArgumentException("URI scheme MUST equal '$SCHEME'.")
            }
            return OpenPgpV4Fingerprint(uri.schemeSpecificPart)
        }
    }
}
