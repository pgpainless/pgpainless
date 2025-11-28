package org.pgpainless.yubikey

import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.OpenPGPKeyVersion
import java.util.*

class YubikeyKeyGeneratorTest {
    val ADMIN_PIN: CharArray = "12345678".toCharArray()

    @Test
    fun generateKey() {
        val helper = YubikeyHelper()
        val keyGen = YubikeyKeyGenerator(PGPainless.getInstance())
        val key = keyGen.generateModernKey(helper.listDevices().first(), ADMIN_PIN, OpenPGPKeyVersion.v4, Date())
        println(key.toAsciiArmoredString())
    }
}
