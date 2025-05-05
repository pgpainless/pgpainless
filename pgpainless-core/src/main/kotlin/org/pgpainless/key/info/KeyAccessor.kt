// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info

import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites.Combination
import java.util.*
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPCertificateComponent
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPIdentityComponent
import org.pgpainless.algorithm.AEADCipherMode
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.toAEADCipherModes
import org.pgpainless.bouncycastle.extensions.toCompressionAlgorithms
import org.pgpainless.bouncycastle.extensions.toHashAlgorithms
import org.pgpainless.bouncycastle.extensions.toSymmetricKeyAlgorithms

abstract class KeyAccessor(
    protected val key: OpenPGPComponentKey,
    private val referenceTime: Date
) {

    abstract val component: OpenPGPCertificateComponent

    val preferredSymmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>
        get() =
            component.getSymmetricCipherPreferences(referenceTime)?.toSymmetricKeyAlgorithms()
                ?: setOf()

    val preferredHashAlgorithms: Set<HashAlgorithm>
        get() = component.getHashAlgorithmPreferences(referenceTime)?.toHashAlgorithms() ?: setOf()

    val preferredCompressionAlgorithms: Set<CompressionAlgorithm>
        get() =
            component.getCompressionAlgorithmPreferences(referenceTime)?.toCompressionAlgorithms()
                ?: setOf()

    val preferredAEADCipherSuites: Set<AEADCipherMode>
        get() =
            component.getAEADCipherSuitePreferences(referenceTime)
                ?.rawAlgorithms
                ?.map { AEADCipherMode(it) }
                ?.toSet() ?: setOf()

    val features: Set<Feature>
        get() =
            Feature.fromBitmask(component.getFeatures(referenceTime)?.features?.toInt() ?: 0)
                .toSet()

    /**
     * Address the key via a user-id (e.g. `Alice <alice@wonderland.lit>`). In this case we are
     * sourcing preferred algorithms from the user-id certification first.
     */
    class ViaUserId(
        key: OpenPGPComponentKey,
        userId: OpenPGPIdentityComponent,
        referenceTime: Date = Date()
    ) : KeyAccessor(key, referenceTime) {
        override val component: OpenPGPCertificateComponent = userId
    }

    /**
     * Address the key via key-id. In this case we are sourcing preferred algorithms from the keys
     * direct-key signature first.
     */
    class ViaKeyIdentifier(key: OpenPGPComponentKey, referenceTime: Date = Date()) :
        KeyAccessor(key, referenceTime) {
        override val component: OpenPGPCertificateComponent = key
    }
}
