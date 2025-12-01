package org.pgpainless.yubikey

import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation
import org.opentest4j.TestAbortedException
import org.pgpainless.PGPainless
import java.util.Properties

abstract class YubikeyTest() {

    val adminPin: CharArray
    val userPin: CharArray
    val allowedSerialNumber: Int

    init {
        javaClass.classLoader.getResourceAsStream("yubikey.properties").use {
            val props = Properties().apply { load(it) }

            adminPin = getProperty(props, "ADMIN_PIN").toCharArray()
            userPin = getProperty(props, "USER_PIN").toCharArray()
            allowedSerialNumber = getProperty(props, "ALLOWED_DEVICE_SERIAL").toInt()
        }
    }

    open val api: PGPainless = PGPainless(BcOpenPGPImplementation()).apply {
        hardwareTokenBackends.add(YubikeyHardwareTokenBackend())
    }

    open val helper: YubikeyHelper = YubikeyHelper(api)

    val yubikey: Yubikey = YubikeyHelper().listDevices().find { it.serialNumber == allowedSerialNumber }
        ?: throw TestAbortedException("No allowed device found.")

    private fun getProperty(properties: Properties, key: String): String {
        return properties.getProperty(key)
            ?: throw TestAbortedException("Could not find property $key in pgpainless-yubikey/src/test/resources/yubikey.properties")
    }
}
