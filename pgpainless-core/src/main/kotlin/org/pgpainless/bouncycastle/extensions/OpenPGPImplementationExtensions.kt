// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.api.EncryptedDataPacketType
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.PGPDigestCalculator

fun OpenPGPImplementation.checksumCalculator(): PGPDigestCalculator {
    return pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
}

fun OpenPGPImplementation.pgpDataEncryptorBuilder(
    mechanism: MessageEncryptionMechanism
): PGPDataEncryptorBuilder {
    require(mechanism.isEncrypted) { "Cannot create PGPDataEncryptorBuilder for NULL algorithm." }
    return pgpDataEncryptorBuilder(mechanism.symmetricKeyAlgorithm).also {
        when (mechanism.mode!!) {
            EncryptedDataPacketType.SED -> it.setWithIntegrityPacket(false)
            EncryptedDataPacketType.SEIPDv1 -> it.setWithIntegrityPacket(true)
            EncryptedDataPacketType.SEIPDv2 -> {
                it.setWithAEAD(mechanism.aeadAlgorithm, mechanism.symmetricKeyAlgorithm)
                it.setUseV6AEAD()
            }
            EncryptedDataPacketType.LIBREPGP_OED -> {
                it.setWithAEAD(mechanism.aeadAlgorithm, mechanism.symmetricKeyAlgorithm)
                it.setUseV5AEAD()
            }
        }

        return it
    }
}
