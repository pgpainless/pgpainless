// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle

import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.util.encoders.Base64
import org.pgpainless.decryption_verification.CustomPublicKeyDataDecryptorFactory
import org.pgpainless.key.SubkeyIdentifier

/**
 * Implementation of the [PublicKeyDataDecryptorFactory] which caches decrypted session keys. That
 * way, if a message needs to be decrypted multiple times, expensive private key operations can be
 * omitted.
 *
 * This implementation changes the behavior or [recoverSessionData] to first return any cache hits.
 * If no hit is found, the method call is delegated to the underlying
 * [PublicKeyDataDecryptorFactory]. The result of that is then placed in the cache and returned.
 */
class CachingBcPublicKeyDataDecryptorFactory(
    privateKey: PGPPrivateKey,
    override val subkeyIdentifier: SubkeyIdentifier
) : BcPublicKeyDataDecryptorFactory(privateKey), CustomPublicKeyDataDecryptorFactory {

    private val cachedSessions: MutableMap<String, ByteArray> = mutableMapOf()

    override fun recoverSessionData(
        keyAlgorithm: Int,
        secKeyData: Array<out ByteArray>
    ): ByteArray =
        lookupSessionKeyData(secKeyData)
            ?: costlyRecoverSessionData(keyAlgorithm, secKeyData).also {
                cacheSessionKeyData(secKeyData, it)
            }

    private fun lookupSessionKeyData(secKeyData: Array<out ByteArray>): ByteArray? =
        cachedSessions[toKey(secKeyData)]?.clone()

    private fun costlyRecoverSessionData(
        keyAlgorithm: Int,
        secKeyData: Array<out ByteArray>
    ): ByteArray = super.recoverSessionData(keyAlgorithm, secKeyData)

    private fun cacheSessionKeyData(secKeyData: Array<out ByteArray>, sessionKey: ByteArray) {
        cachedSessions[toKey(secKeyData)] = sessionKey.clone()
    }

    private fun toKey(secKeyData: Array<out ByteArray>): String =
        Base64.toBase64String(secKeyData[0])

    fun clear() {
        cachedSessions.clear()
    }
}
