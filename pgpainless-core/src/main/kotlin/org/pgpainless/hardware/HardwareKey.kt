// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.hardware

/**
 * Represents a single cryptographic key stored on a [HardwareToken].
 *
 * @param label 20 octets of label, such as the keys v4 fingerprint.
 * @param identifier slot identifier
 */
data class HardwareKey(val label: ByteArray, val identifier: Any) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HardwareKey

        if (!label.contentEquals(other.label)) return false
        if (identifier != other.identifier) return false

        return true
    }

    override fun hashCode(): Int {
        var result = label.contentHashCode()
        result = 31 * result + identifier.hashCode()
        return result
    }
}
