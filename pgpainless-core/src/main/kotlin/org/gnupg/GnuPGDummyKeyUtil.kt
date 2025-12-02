// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.gnupg

import kotlin.experimental.and
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.bcpg.SecretSubkeyPacket
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.gnupg.GnuPGDummyKeyUtil.KeyFilter
import org.pgpainless.key.SubkeyIdentifier

/**
 * This class can be used to remove private keys from secret software-keys by replacing them with
 * stub secret keys in the style of GnuPGs proprietary extensions.
 *
 * @see
 *   [GnuPGs doc/DETAILS - GNU extensions to the S2K algorithm](https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;hb=HEAD#l1489)
 */
class GnuPGDummyKeyUtil private constructor() {

    companion object {

        /**
         * Return the key-ids of all keys which appear to be stored on a hardware token / smartcard
         * by GnuPG. Note, that this functionality is based on GnuPGs proprietary S2K extensions,
         * which are not strictly required for dealing with hardware-backed keys.
         *
         * @param secretKeys secret keys
         * @return set of keys with S2K type [S2K.GNU_DUMMY_S2K] and protection mode
         *   [GnuPGDummyExtension.DIVERT_TO_CARD]
         */
        @JvmStatic
        fun getIdsOfKeysWithGnuPGS2KDivertedToCard(
            secretKeys: PGPSecretKeyRing
        ): Set<SubkeyIdentifier> =
            secretKeys
                .filter {
                    it.s2K?.type == S2K.GNU_DUMMY_S2K &&
                        it.s2K?.protectionMode == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD
                }
                .map { SubkeyIdentifier(secretKeys, it.keyIdentifier) }
                .toSet()

        @JvmStatic fun modify(key: OpenPGPKey): Builder = modify(key.pgpSecretKeyRing)

        /**
         * Modify the given [PGPSecretKeyRing].
         *
         * @param secretKeys secret keys
         * @return builder
         */
        @JvmStatic fun modify(secretKeys: PGPSecretKeyRing) = Builder(secretKeys)

        @JvmStatic
        fun serialToBytes(sn: Int) =
            byteArrayOf(
                (sn shr 24).toByte(), (sn shr (16)).toByte(), (sn shr (8)).toByte(), sn.toByte())
    }

    class Builder(private val keys: PGPSecretKeyRing) {

        /**
         * Remove all private keys that match the given [KeyFilter] from the key ring and replace
         * them with GNU_DUMMY keys with S2K protection mode [GnuPGDummyExtension.NO_PRIVATE_KEY].
         *
         * @param filter filter to select keys for removal
         * @return modified key ring
         */
        fun removePrivateKeys(filter: KeyFilter): PGPSecretKeyRing {
            return replacePrivateKeys(GnuPGDummyExtension.NO_PRIVATE_KEY, null, filter)
        }

        /**
         * Remove all private keys that match the given [KeyFilter] from the key ring and replace
         * them with GNU_DUMMY keys with S2K protection mode [GnuPGDummyExtension.DIVERT_TO_CARD].
         * This method will set the serial number of the card to 0x00000000000000000000000000000000.
         * NOTE: This method does not actually move any keys to a card.
         *
         * @param filter filter to select keys for removal
         * @return modified key ring
         */
        fun divertPrivateKeysToCard(filter: KeyFilter): PGPSecretKeyRing {
            return divertPrivateKeysToCard(filter, ByteArray(16))
        }

        /**
         * Remove all private keys that match the given [KeyFilter] from the key ring and replace
         * them with GNU_DUMMY keys with S2K protection mode [GnuPGDummyExtension.DIVERT_TO_CARD].
         * This method will include the card serial number into the encoded dummy key. NOTE: This
         * method does not actually move any keys to a card.
         *
         * @param filter filter to select keys for removal
         * @param cardSerialNumber serial number of the card (at most 16 bytes long)
         * @return modified key ring
         */
        fun divertPrivateKeysToCard(
            filter: KeyFilter,
            cardSerialNumber: ByteArray?
        ): PGPSecretKeyRing {
            require(cardSerialNumber == null || cardSerialNumber.size <= 16) {
                "Card serial number length cannot exceed 16 bytes."
            }
            return replacePrivateKeys(GnuPGDummyExtension.DIVERT_TO_CARD, cardSerialNumber, filter)
        }

        private fun replacePrivateKeys(
            extension: GnuPGDummyExtension,
            serial: ByteArray?,
            filter: KeyFilter
        ): PGPSecretKeyRing {
            val encodedSerial: ByteArray? = serial?.let { encodeSerial(it) }
            val s2k: S2K = extensionToS2K(extension)

            return PGPSecretKeyRing(
                keys
                    .map {
                        if (!filter.filter(it.keyIdentifier)) {
                            // Leave non-filtered key intact
                            it
                        } else {
                            val publicKeyPacket = it.publicKey.publicKeyPacket
                            // Convert key packet
                            val keyPacket: SecretKeyPacket =
                                if (it.isMasterKey) {
                                    SecretKeyPacket(
                                        publicKeyPacket,
                                        0,
                                        SecretKeyPacket.USAGE_SHA1,
                                        s2k,
                                        null,
                                        encodedSerial)
                                } else {
                                    SecretSubkeyPacket(
                                        publicKeyPacket,
                                        0,
                                        SecretKeyPacket.USAGE_SHA1,
                                        s2k,
                                        null,
                                        encodedSerial)
                                }
                            PGPSecretKey(keyPacket, it.publicKey)
                        }
                    }
                    .toList())
        }

        private fun encodeSerial(serial: ByteArray): ByteArray {
            val encoded = ByteArray(serial.size + 1)
            encoded[0] = serial.size.toByte().and(0xff.toByte())
            System.arraycopy(serial, 0, encoded, 1, serial.size)
            return encoded
        }

        private fun extensionToS2K(extension: GnuPGDummyExtension): S2K {
            return S2K.gnuDummyS2K(
                if (extension == GnuPGDummyExtension.DIVERT_TO_CARD)
                    S2K.GNUDummyParams.divertToCard()
                else S2K.GNUDummyParams.noPrivateKey())
        }
    }

    /** Filter for selecting keys. */
    fun interface KeyFilter {
        fun filter(keyIdentifier: KeyIdentifier): Boolean

        companion object {

            /**
             * Select any key.
             *
             * @return filter
             */
            @JvmStatic fun any(): KeyFilter = KeyFilter { true }

            /**
             * Select only the given keyId.
             *
             * @param onlyKeyId only acceptable key id
             * @return filter
             */
            @JvmStatic
            @Deprecated("Use only(KeyIdentifier) instead.")
            fun only(onlyKeyId: Long) = only(KeyIdentifier(onlyKeyId))

            /**
             * Select only the given keyIdentifier.
             *
             * @param onlyKeyIdentifier only acceptable key identifier
             * @return filter
             */
            @JvmStatic
            fun only(onlyKeyIdentifier: KeyIdentifier) = KeyFilter {
                it.matchesExplicit(onlyKeyIdentifier)
            }

            /**
             * Select all keyIds which are contained in the given set of ids.
             *
             * @param ids set of acceptable keyIds
             * @return filter
             */
            @JvmStatic fun selected(ids: Collection<KeyIdentifier>) = KeyFilter { ids.contains(it) }
        }
    }
}
