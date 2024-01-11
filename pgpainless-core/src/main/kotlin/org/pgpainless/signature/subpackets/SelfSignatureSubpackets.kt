// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import java.util.*
import openpgp.plusSeconds
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.bcpg.sig.KeyExpirationTime
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.bcpg.sig.PreferredAlgorithms
import org.bouncycastle.bcpg.sig.PrimaryUserID
import org.bouncycastle.bcpg.sig.RevocationKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.pgpainless.algorithm.*

interface SelfSignatureSubpackets : BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<SelfSignatureSubpackets> {
        fun then(nextCallback: SignatureSubpacketCallback<SelfSignatureSubpackets>): Callback {
            val currCallback = this
            return object : Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    currCallback.modifyHashedSubpackets(hashedSubpackets)
                    nextCallback.modifyHashedSubpackets(hashedSubpackets)
                }

                override fun modifyUnhashedSubpackets(unhashedSubpackets: SelfSignatureSubpackets) {
                    currCallback.modifyUnhashedSubpackets(unhashedSubpackets)
                    nextCallback.modifyUnhashedSubpackets(unhashedSubpackets)
                }
            }
        }
    }

    fun setKeyFlags(vararg keyflags: KeyFlag): SelfSignatureSubpackets

    fun setKeyFlags(keyFlags: List<KeyFlag>): SelfSignatureSubpackets

    fun setKeyFlags(isCritical: Boolean, vararg keyFlags: KeyFlag): SelfSignatureSubpackets

    fun setKeyFlags(keyFlags: KeyFlags?): SelfSignatureSubpackets

    fun getKeyFlags(): List<KeyFlag>? = getKeyFlagsPacket()?.let { KeyFlag.fromBitmask(it.flags) }

    fun getKeyFlagsPacket(): KeyFlags?

    fun setPrimaryUserId(): SelfSignatureSubpackets

    fun setPrimaryUserId(isCritical: Boolean): SelfSignatureSubpackets

    fun setPrimaryUserId(primaryUserID: PrimaryUserID?): SelfSignatureSubpackets

    fun getPrimaryUserId(): Boolean? = getPrimaryUserIdPacket()?.isPrimaryUserID

    fun getPrimaryUserIdPacket(): PrimaryUserID?

    fun setKeyExpirationTime(key: PGPPublicKey, keyExpirationTime: Date?): SelfSignatureSubpackets

    fun setKeyExpirationTime(
        keyCreationTime: Date,
        keyExpirationTime: Date?
    ): SelfSignatureSubpackets

    fun setKeyExpirationTime(
        isCritical: Boolean,
        keyCreationTime: Date,
        keyExpirationTime: Date?
    ): SelfSignatureSubpackets

    fun setKeyExpirationTime(
        isCritical: Boolean,
        secondsFromCreationToExpiration: Long
    ): SelfSignatureSubpackets

    fun setKeyExpirationTime(keyExpirationTime: KeyExpirationTime?): SelfSignatureSubpackets

    fun getKeyExpirationTime(keyCreationTime: Date): Date? =
        getKeyExpirationTimePacket()?.let {
            if (it.time == 0L) {
                null
            } else {
                keyCreationTime.plusSeconds(it.time)
            }
        }

    fun getKeyExpirationTimePacket(): KeyExpirationTime?

    fun setPreferredCompressionAlgorithms(
        vararg algorithms: CompressionAlgorithm
    ): SelfSignatureSubpackets

    fun setPreferredCompressionAlgorithms(
        algorithms: Collection<CompressionAlgorithm>
    ): SelfSignatureSubpackets

    fun setPreferredCompressionAlgorithms(
        isCritical: Boolean,
        algorithms: Collection<CompressionAlgorithm>
    ): SelfSignatureSubpackets

    fun setPreferredCompressionAlgorithms(
        preferredAlgorithms: PreferredAlgorithms?
    ): SelfSignatureSubpackets

    fun getPreferredCompressionAlgorithms(): Set<CompressionAlgorithm> =
        SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(
            getPreferredCompressionAlgorithmsPacket())

    fun getPreferredCompressionAlgorithmsPacket(): PreferredAlgorithms?

    fun setPreferredSymmetricKeyAlgorithms(
        vararg algorithms: SymmetricKeyAlgorithm
    ): SelfSignatureSubpackets

    fun setPreferredSymmetricKeyAlgorithms(
        algorithms: Collection<SymmetricKeyAlgorithm>
    ): SelfSignatureSubpackets

    fun setPreferredSymmetricKeyAlgorithms(
        isCritical: Boolean,
        algorithms: Collection<SymmetricKeyAlgorithm>
    ): SelfSignatureSubpackets

    fun setPreferredSymmetricKeyAlgorithms(
        algorithms: PreferredAlgorithms?
    ): SelfSignatureSubpackets

    fun getPreferredSymmetricKeyAlgorithms(): Set<SymmetricKeyAlgorithm> =
        SignatureSubpacketsUtil.parsePreferredSymmetricKeyAlgorithms(
            getPreferredSymmetricKeyAlgorithmsPacket())

    fun getPreferredSymmetricKeyAlgorithmsPacket(): PreferredAlgorithms?

    fun setPreferredHashAlgorithms(vararg algorithms: HashAlgorithm): SelfSignatureSubpackets

    fun setPreferredHashAlgorithms(algorithms: Collection<HashAlgorithm>): SelfSignatureSubpackets

    fun setPreferredHashAlgorithms(
        isCritical: Boolean,
        algorithms: Collection<HashAlgorithm>
    ): SelfSignatureSubpackets

    fun setPreferredHashAlgorithms(algorithms: PreferredAlgorithms?): SelfSignatureSubpackets

    fun getPreferredHashAlgorithms(): Set<HashAlgorithm> =
        SignatureSubpacketsUtil.parsePreferredHashAlgorithms(getPreferredHashAlgorithmsPacket())

    fun getPreferredHashAlgorithmsPacket(): PreferredAlgorithms?

    fun addRevocationKey(revocationKey: PGPPublicKey): SelfSignatureSubpackets

    fun addRevocationKey(isCritical: Boolean, revocationKey: PGPPublicKey): SelfSignatureSubpackets

    fun addRevocationKey(
        isCritical: Boolean,
        isSensitive: Boolean,
        revocationKey: PGPPublicKey
    ): SelfSignatureSubpackets

    fun addRevocationKey(revocationKey: RevocationKey): SelfSignatureSubpackets

    fun getRevocationKeyPackets(): List<RevocationKey>

    fun clearRevocationKeys(): SelfSignatureSubpackets

    fun setFeatures(vararg features: Feature): SelfSignatureSubpackets

    fun setFeatures(isCritical: Boolean, vararg features: Feature): SelfSignatureSubpackets

    fun setFeatures(features: Features?): SelfSignatureSubpackets

    companion object {

        /** Factory method for a [Callback] that does nothing. */
        @JvmStatic fun nop() = object : Callback {}

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the hashed
         * subpacket area of a [SelfSignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = SelfSignatureSubpackets.applyHashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyHashed(function: SelfSignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    function(hashedSubpackets)
                }
            }
        }

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the unhashed
         * subpacket area of a [SelfSignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = SelfSignatureSubpackets.applyUnhashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyUnhashed(function: SelfSignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyUnhashedSubpackets(unhashedSubpackets: SelfSignatureSubpackets) {
                    function(unhashedSubpackets)
                }
            }
        }

        @JvmStatic fun defaultCallback() = object : Callback {}
    }
}
