// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.signature.subpackets.SignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper
import java.util.*

data class KeySpec(
        val keyType: KeyType,
        val subpacketGenerator: SignatureSubpackets,
        val isInheritedSubPackets: Boolean,
        val keyCreationDate: Date
) {

    val subpackets: PGPSignatureSubpacketVector
        get() = SignatureSubpacketsHelper.toVector(subpacketGenerator)

    companion object {
        @JvmStatic
        fun getBuilder(type: KeyType, flag: KeyFlag, vararg flags: KeyFlag) = KeySpecBuilder(type, flag, *flags)
    }
}