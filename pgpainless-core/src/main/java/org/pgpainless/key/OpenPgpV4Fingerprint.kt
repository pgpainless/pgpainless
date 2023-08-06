package org.pgpainless.key

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.util.encoders.Hex
import java.net.URI
import java.nio.Buffer
import java.nio.ByteBuffer
import java.nio.charset.Charset

class OpenPgpV4Fingerprint: OpenPgpFingerprint {

    constructor(fingerprint: String): super(fingerprint)
    constructor(bytes: ByteArray): super(bytes)
    constructor(key: PGPPublicKey): super(key)
    constructor(key: PGPSecretKey): super(key)
    constructor(keys: PGPKeyRing): super(keys)

    override fun getVersion() = 4

    override val keyId: Long
        get() {
            val bytes = Hex.decode(toString().toByteArray(Charset.forName("UTF-8")))
            val buf = ByteBuffer.wrap(bytes)

            // The key id is the right-most 8 bytes (conveniently a long)
            // We have to cast here in order to be compatible with java 8
            // https://github.com/eclipse/jetty.project/issues/3244
            (buf as Buffer).position(12) // 20 - 8 bytes = offset 12
            return buf.getLong()
        }

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
            for (i in 5 .. 8) {
                append(fingerprint, i * 4, (i + 1) * 4).append(' ')
            }
            append(fingerprint, 36, 40)
        }
    }

    companion object {
        @JvmStatic
        val SCHEME = "openpgp4fpr"

        @JvmStatic
        fun fromUri(uri: URI): OpenPgpV4Fingerprint {
            if (SCHEME != uri.scheme) {
                throw IllegalArgumentException("URI scheme MUST equal '$SCHEME'.")
            }
            return OpenPgpV4Fingerprint(uri.schemeSpecificPart)
        }
    }
}