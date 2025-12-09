package org.bouncycastle.openpgp.hardware

interface HardwareToken {

    val keys: Map<ByteArray, HardwareKey>
}
