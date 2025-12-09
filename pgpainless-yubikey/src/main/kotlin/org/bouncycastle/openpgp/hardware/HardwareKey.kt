package org.bouncycastle.openpgp.hardware

/**
 * Represents a single cryptographic key stored on a [HardwareToken].
 *
 * @param label 20 octets of label, such as the keys v4 fingerprint.
 * @param identifier slot identifier
 */
open class HardwareKey<I>(val label: ByteArray, val identifier: I) {

}
